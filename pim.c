/*
 * This file is part of:
 *	pimky - Slimline PIM Routing Daemon for IPv4 and IPv6
 * Copyright (C) 2010  Alexander Clouter <alex@digriz.org.uk>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA
 * or alternatively visit <http://www.gnu.org/licenses/gpl.html>
 */

#include "pimky.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>

#if defined(__linux__)
#include <linux/mroute.h>
#include <linux/mroute6.h>
#elif defined(__FreeBSD__)
#include <netinet/ip_mroute.h>
#include <netinet6/ip6_mroute.h>
#endif

int pim_init(int sock)
{
	int			type, sl, loop;
	int			v;
	int			ret;
	struct icmp6_filter	filter;
	int			pim;

	type = socktype(sock);
	if (type < 0)
		return type;

	sl = family_to_level(type);
	if (sl < 0)
		return sl;

	v = 1;
	switch (type) {
	case AF_INET:
		ret = setsockopt(sock, sl, MRT_INIT, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT_INIT)");
			goto exit;
		}

#ifdef __linux__
		ret = setsockopt(sock, sl, MRT_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT_PIM)");
			goto exit;
		}
#endif

		break;
	case AF_INET6:
		ret = setsockopt(sock, sl, MRT6_INIT, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT6_INIT)");
			goto exit;
		}

		ICMP6_FILTER_SETBLOCKALL(&filter);
		ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER,
				&filter, sizeof(filter));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(ICMP6_FILTER)");
			goto exit;
		}

		ret = setsockopt(sock, sl, MRT6_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT6_PIM)");
			goto exit;
		}

		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d",
				__func__, type);
		return -EX_SOFTWARE;
	}

	pim = socket(type, SOCK_RAW, IPPROTO_PIM);
	if (pim < 0) {
		logger(LOG_ERR, errno, "socket(SOCK_RAW, IPPROTO_PIM)");
		goto exit;
	}

	if (sl == IPPROTO_IP)
		loop = IP_MULTICAST_LOOP;
	else
		loop = IPV6_MULTICAST_LOOP;
	v = 0;
	ret = setsockopt(sock, sl, loop, &v, sizeof(v));
	if (!ret)
		ret = setsockopt(pim, sl, loop, &v, sizeof(v));
	if (ret < 0) {
		logger(LOG_ERR, errno, "setsockopt(MULTICAST_LOOP)");
		goto pim;
	}

	ret = pim_register(sock);
	if (ret < 0)
		goto pim;

	return pim;

pim:
	close(pim);
exit:
	return -EX_OSERR;
}

int pim_shutdown(int sock)
{
	int			type, sl;
	int			v = 0;
	int			ret;

	type = socktype(sock);
	if (type < 0)
		return type;

	sl = family_to_level(type);
	if (sl < 0)
		return sl;

	switch (type) {
	case AF_INET:
#ifdef __linux__
		ret = setsockopt(sock, sl, MRT_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT_PIM)");
			return -EX_OSERR;
		}
#endif

		ret = setsockopt(sock, sl, MRT_DONE, NULL, 0);
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT_INIT)");
			return -EX_OSERR;
		}

		break;
	case AF_INET6:
		ret = setsockopt(sock, sl, MRT6_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT6_PIM)");
			return -EX_OSERR;
		}

		ret = setsockopt(sock, sl, MRT6_DONE, NULL, 0);
		if (ret < 0) {
			logger(LOG_ERR, errno, "setsockopt(MRT6_INIT)");
			return -EX_OSERR;
		}

		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d",
				__func__, type);
		return -EX_SOFTWARE;
	}

	return EX_OK;
}

int pim_hello_opt_add(unsigned char **buf, size_t len, unsigned int opt,
		struct sockaddr_storage *ss, struct iface_map *ifm)
{
	union sockstore		*store = (union sockstore *) ss;
	union sockstore		*storeaddr;
	struct iface_map_addr	*ifa = ifm->addr;
	struct iface_info	*ifi = ifm->info;
	struct pimopt		*option;
	unsigned int		optlen, i;
	unsigned char		*payload;

	switch (opt) {
	case PIM_OPT_HOLDTIME:
		optlen = sizeof(option->value.holdtime);
		break;
	case PIM_OPT_DR_PRIORITY:
		optlen = sizeof(option->value.dr_priority);
		break;
	case PIM_OPT_GENERATION_ID:
		optlen = sizeof(option->value.generation_id);
		break;
	case PIM_OPT_ADDRESS_LIST:
		optlen = 0;
		switch (store->sa.sa_family) {
		case AF_INET:
			optlen = (ifm->ip.v4 - 1)*(2 + sizeof(struct in_addr));
			break;
		case AF_INET6:
			optlen = (ifm->ip.v6 - 1)*(2 + sizeof(struct in6_addr));
			break;
		}
		/* no secondary addresses */
		if (optlen == 0)
			return len;
		break;
	default:
		logger(LOG_ERR, 0, "unknown PIM hello option: %d", opt);
		return -EX_SOFTWARE;
	}

	*buf = realloc(*buf, len + 2*sizeof(uint16_t) + optlen);
	if (*buf == NULL) {
		logger(LOG_ERR, errno, "realloc() for pimopt appending");
		return -EX_OSERR;
	}

	option		= (struct pimopt *) &(*buf)[len];
	option->type	= htons(opt);
	option->len	= htons(optlen);

	switch (opt) {
	case PIM_OPT_HOLDTIME:
		if (running)
			option->value.holdtime	= htons(RFC4601_Default_Hello_Holdtime);
		else
			option->value.holdtime	= htons(0);
		break;
	case PIM_OPT_DR_PRIORITY:
		option->value.dr_priority	= htonl(ifi->dr_priority);
		break;
	case PIM_OPT_GENERATION_ID:
		option->value.generation_id	= htonl(ifi->generation_id);
		break;
	case PIM_OPT_ADDRESS_LIST:
		payload = &(*buf)[len + 2*sizeof(uint16_t)];
		i = 0;
		for (ifa = ifa->next; ifa != NULL; ifa = ifa->next) {
			storeaddr = (union sockstore *) &ifa->addr;

			if (storeaddr->sa.sa_family != store->sa.sa_family)
				continue;

			switch (storeaddr->sa.sa_family) {
			case AF_INET:
				if (storeaddr->s4.sin_addr.s_addr == store->s4.sin_addr.s_addr)
					continue;

				payload[i+0] = IANA_AFI_IPV4;
				payload[i+1] = 0;
				memcpy(&payload[i+2],
						&storeaddr->s4.sin_addr.s_addr,
						sizeof(struct in_addr));
				i += 2 + sizeof(struct in_addr);
				break;
			case AF_INET6:
				if (IN6_ARE_ADDR_EQUAL(&storeaddr->s6.sin6_addr, &store->s6.sin6_addr))
					continue;

				payload[i+0] = IANA_AFI_IPV6;
				payload[i+1] = 0;
				memcpy(&payload[i+2],
						&storeaddr->s6.sin6_addr,
						sizeof(struct in6_addr));
				i += 2 + sizeof(struct in6_addr);
				break;
			}
		}
		break;
	}

	return len + 2*sizeof(uint16_t) + optlen;
}

void pim_hello_send(void)
{
	struct iface_map	*ifm;
	union sockstore		store;
	int			ret;
	unsigned char		*pimpkt, *lpimpkt;
	struct pimhdr		*pim;
	unsigned int		len, llen;
	struct ip_mreqn		mreq;
	struct ip6_phdr		*ip6;
	struct sockaddr_storage src;

	fprintf(stderr, "sent pim hello\n");

	memset(&mreq, 0, sizeof(mreq));

	for (ifm = iface_map.next; ifm != NULL; ifm = ifm->next) {
		len	= sizeof(struct pimhdr);

		pimpkt = malloc(len);
		if (pimpkt == NULL) {
			logger(LOG_ERR, errno, "malloc() for pim hello packet");
			continue;
		}
		memset(pimpkt, 0, len);

		pim		= (struct pimhdr *) pimpkt;
		pim->ver	= 2;
		pim->type	= PIM_HELLO;

		len = pim_hello_opt_add(&pimpkt, len,
				PIM_OPT_HOLDTIME, NULL, ifm);
		if (len < 0)
			goto free;
		len = pim_hello_opt_add(&pimpkt, len,
				PIM_OPT_DR_PRIORITY, NULL, ifm);
		if (len < 0)
			goto free;
		len = pim_hello_opt_add(&pimpkt, len,
				PIM_OPT_GENERATION_ID, NULL, ifm);
		if (len < 0)
			goto free;

		if (ifm->ip.v4) {
			lpimpkt	= malloc(len);
			if (lpimpkt == NULL) {
				logger(LOG_ERR, errno, "malloc() for v4 pim hello packet");
				goto exit_v4;
			}
			memcpy(lpimpkt, pimpkt, len);

			llen			= len;

			store.ss.ss_family	= AF_INET;

			store.s4.sin_port	= htons(IPPROTO_PIM);
			inet_pton(AF_INET, "224.0.0.13", &store.s4.sin_addr);

			ret = mcast_join(mroute4, ifm->index, &store.ss);
			assert(ret == EX_OK || ret == -EX_TEMPFAIL);

			ret = route_getsrc(ifm->index, &store.ss, &src);
			assert(ret == EX_OK);

			llen = pim_hello_opt_add(&lpimpkt, llen,
					PIM_OPT_ADDRESS_LIST, &src, ifm);
			if (llen < 0)
				goto free_v4;

			pim		= (struct pimhdr *) lpimpkt;
			pim->cksum	= in_cksum(pim, llen);

			mreq.imr_ifindex = ifm->index;
			ret = setsockopt(pim4, IPPROTO_IP, IP_MULTICAST_IF,
					&mreq, sizeof(mreq));
			if (ret == 0)
				ret = _sendto(pim4, pim, llen, 0,
						&store.sa, sizeof(store));
			if (ret == -1)
				logger(LOG_ERR, errno, "unable to send pim4"
							" on %s", ifm->name);
free_v4:
			free(lpimpkt);
exit_v4:
			;
		}
		if (ifm->ip.v6) {
			lpimpkt	= malloc(sizeof(struct ip6_phdr) + len);
			if (lpimpkt == NULL) {
				logger(LOG_ERR, errno, "malloc() for v6 pim hello packet");
				goto exit_v6;
			}
			memcpy(&lpimpkt[sizeof(struct ip6_phdr)], pimpkt, len);

			llen			= sizeof(struct ip6_phdr) + len;

			store.ss.ss_family	= AF_INET6;

			store.s6.sin6_port	= htons(IPPROTO_PIM);
			store.s6.sin6_scope_id	= ifm->index;
			inet_pton(AF_INET6, "ff02::d", &store.s6.sin6_addr);

			ret = mcast_join(mroute6, ifm->index, &store.ss);
			assert(ret == EX_OK || ret == -EX_TEMPFAIL);

			ret = route_getsrc(ifm->index, &store.ss, &src);
			assert(ret == EX_OK);

			llen = pim_hello_opt_add(&lpimpkt, llen,
					PIM_OPT_ADDRESS_LIST, &src, ifm);
			if (llen < 0)
				goto free_v6;

			ip6		= (struct ip6_phdr *) lpimpkt;
			memset(ip6, 0, sizeof(struct ip6_phdr));
			memcpy(&ip6->src, &((struct sockaddr_in6 *)&src)->sin6_addr,
					sizeof(struct in6_addr));
			memcpy(&ip6->dst, &store.s6.sin6_addr,
					sizeof(struct in6_addr));
			ip6->len	= htonl(llen - sizeof(struct ip6_phdr));
			ip6->nexthdr	= IPPROTO_PIM;

			pim		= (struct pimhdr *) &lpimpkt[sizeof(struct ip6_phdr)];
			pim->cksum	= in_cksum(ip6, llen);

			ret = _sendto(pim6, pim, llen - sizeof(struct ip6_phdr), 0,
					&store.sa, sizeof(store));
			if (ret == -1)
				logger(LOG_ERR, errno, "unable to send pim6"
							" on %s", ifm->name);
free_v6:
			free(lpimpkt);
exit_v6:
			;
		}
free:
		free(pimpkt);
	}
}

void pim_recv(int sock, void *buf, int len,
		struct sockaddr_storage *src_addr, socklen_t addrlen)
{
	struct ip	*ip;
	struct pimhdr	*pim;

	printf("called %s\n", __func__);

	switch (src_addr->ss_family) {
	case AF_INET:
		ip	= buf;

		assert(ip->ip_v == 4);
		assert(ip->ip_hl >= 5);
		assert(ntohs(ip->ip_len) == len);
		/* TODO do we handle fragments? */
		assert((ntohs(ip->ip_off) & IP_OFFMASK) == 0
				&& (ntohs(ip->ip_off) & (~IP_OFFMASK)) != IP_MF);
		if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)))
			assert(ip->ip_ttl == 1);
		assert(ip->ip_p == IPPROTO_PIM);
		assert(!in_cksum(ip, ip->ip_hl << 2));

		pim	= (struct pimhdr *) ((char *)buf + (ip->ip_hl << 2));

		assert(pim->ver == 2);
		assert(pim->reserved == 0);	/* TODO ignore */
		if (pim->type != PIM_REGISTER)
			assert(!in_cksum(pim, len - (ip->ip_hl << 2)));

		switch (pim->type) {
		case PIM_HELLO:
			printf("got a PIM Hello\n");
			break;
		default:
			printf("got unknown code %d\n", pim->type);
		}

		break;
	case AF_INET6:
		break;
	default:
		logger(LOG_WARNING, 0, "%s(): unknown socket type: %d",
				__func__, src_addr->ss_family);
	}
}

int pim_register(int sock)
{
	struct pimky_ifctl	ifctl;
	int			type;

	type = socktype(sock);
	if (type < 0)
		return type;

	memset(&ifctl, 0, sizeof(ifctl));

	switch (type) {
	case AF_INET:
		ifctl.flags	= VIFF_REGISTER;
		break;
	case AF_INET6:
		ifctl.flags	= MIFF_REGISTER;
		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d",
				__func__, type);
		return -EX_SOFTWARE;
	}

	return vif_add(sock, &ifctl);
}
