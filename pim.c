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
	int			type, slevel, loop;
	int			v;
	int			ret;
	struct icmp6_filter	filter;
	int			pim;

	type = socktype(sock);
	if (type < 0)
		return type;

	slevel = family_to_level(type);
	if (slevel < 0)
		return slevel;

	v = 1;
	switch (type) {
	case AF_INET:
		ret = setsockopt(sock, slevel, MRT_INIT, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_INIT)", __func__);
			goto exit;
		}

#ifdef __linux__
		ret = setsockopt(sock, slevel, MRT_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_PIM)", __func__);
			goto exit;
		}
#endif

		break;
	case AF_INET6:
		ret = setsockopt(sock, slevel, MRT6_INIT, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_INIT)", __func__);
			goto exit;
		}

		ICMP6_FILTER_SETBLOCKALL(&filter);
		ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(ICMP6_FILTER)", __func__);
			goto exit;
		}

		ret = setsockopt(sock, slevel, MRT6_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_PIM)", __func__);
			goto exit;
		}

		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}

	pim = socket(type, SOCK_RAW, IPPROTO_PIM);
	if (pim < 0) {
		logger(LOG_ERR, errno, "%s(): socket(AF_INET, SOCK_RAW, IPPROTO_PIM)", __func__);
		goto exit;
	}

	if (slevel == IPPROTO_IP)
		loop = IP_MULTICAST_LOOP;
	else
		loop = IPV6_MULTICAST_LOOP;
	v = 0;
	ret = setsockopt(sock, slevel, loop, &v, sizeof(v));
	if (!ret)
		ret = setsockopt(pim, slevel, loop, &v, sizeof(v));
	if (ret < 0) {
		logger(LOG_ERR, errno, "%s(): setsockopt(IP[V6]_MULTICAST_LOOP)", __func__);
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
	int			type, slevel;
	int			v = 0;
	int			ret;

	type = socktype(sock);
	if (type < 0)
		return type;

	slevel = family_to_level(type);
	if (slevel < 0)
		return slevel;

	switch (type) {
	case AF_INET:
#ifdef __linux__
		ret = setsockopt(sock, slevel, MRT_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_PIM)", __func__);
			return -EX_OSERR;
		}
#endif

		ret = setsockopt(sock, slevel, MRT_DONE, NULL, 0);
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_INIT)", __func__);
			return -EX_OSERR;
		}

		break;
	case AF_INET6:
		ret = setsockopt(sock, slevel, MRT6_PIM, &v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_PIM)", __func__);
			return -EX_OSERR;
		}

		ret = setsockopt(sock, slevel, MRT6_DONE, NULL, 0);
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_INIT)", __func__);
			return -EX_OSERR;
		}

		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}

	return EX_OK;
}

void pim_hello_send(void)
{
	struct iface_map	*ifm;
	union
	{
		struct sockaddr_storage	ss;
		struct sockaddr_in	s4;
		struct sockaddr_in6	s6;
	} s;
	int			ret;
	char			pimpkt[sizeof(struct ip6_pseudohdr)
					+ sizeof(struct pimhdr)
					+ sizeof(struct pimopt)];
	struct ip6_pseudohdr	*ip6;
	struct pimhdr		*pim;
	struct pimopt		*pimopt;
	struct ip_mreqn		mreq;

	struct sockaddr_storage src;

	fprintf(stderr, "sent pim hello\n");

	memset(pimpkt, 0, sizeof(pimpkt));

	pim	= (struct pimhdr *) &pimpkt[sizeof(struct ip6_pseudohdr)];
	pimopt	= (struct pimopt *) &pimpkt[sizeof(struct ip6_pseudohdr)
						+ sizeof(struct pimhdr)];

	pim->ver			= 2;
	pim->type			= PIM_HELLO;
	pimopt->type			= htons(PIM_OPT_HOLDTIME);
	pimopt->len			= htons(2);
	pimopt->payload.holdtime	= htons(RFC4601_Default_Hello_Holdtime);
	
	for (ifm = iface_map.next; ifm != NULL; ifm = ifm->next) {
		if (ifm->ip.v4) {
			s.ss.ss_family		= AF_INET;

			s.s4.sin_port		= htons(IPPROTO_PIM);
			inet_pton(AF_INET, "224.0.0.13", &s.s4.sin_addr);

			ret = mcast_join(mroute4, ifm->index, &s.ss);
			assert(ret == EX_OK || ret == -EX_TEMPFAIL);

			pim->cksum		= cksum(pim, sizeof(struct pimhdr) 
								+ sizeof(struct pimopt));

			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_ifindex = ifm->index;
			ret = setsockopt(pim4, IPPROTO_IP, IP_MULTICAST_IF,
					&mreq, sizeof(mreq));
			if (!ret)
				ret = sendto(pim4, pim, sizeof(struct pimhdr) + sizeof(struct pimopt),
						0, (struct sockaddr *) &s.ss, sizeof(s.ss));
			if (ret < 0)
				logger(LOG_ERR, errno, "unable to send pim4 on %s", ifm->name);

		}
		if (ifm->ip.v6) {
			s.ss.ss_family		= AF_INET6;

			s.s6.sin6_port		= htons(IPPROTO_PIM);
			s.s6.sin6_scope_id	= ifm->index;
			inet_pton(AF_INET6, "ff02::d", &s.s6.sin6_addr);

			ip6 = (struct ip6_pseudohdr *) &pimpkt;
			route_getsrc(ifm->index, &s.ss, &src);
			memcpy(&ip6->src, &((struct sockaddr_in6 *)&src)->sin6_addr, sizeof(struct in6_addr));
			memcpy(&ip6->dst, &s.s6.sin6_addr, sizeof(struct in6_addr));
			ip6->nexthdr = s.s6.sin6_port;
			ip6->len = sizeof(struct pimhdr) + sizeof(struct pimopt);

			pim->cksum		= cksum(ip6, sizeof(struct ip6_pseudohdr)
								+ sizeof(struct pimhdr) 
								+ sizeof(struct pimopt));

			ret = mcast_join(mroute6, ifm->index, &s.ss);
			assert(ret == EX_OK || ret == -EX_TEMPFAIL);

			ret = sendto(pim6, pim, sizeof(struct pimhdr) + sizeof(struct pimopt),
					0, (struct sockaddr *) &s.ss, sizeof(s.ss));
			if (ret < 0)
				logger(LOG_ERR, errno, "unable to send pim6 on %s", ifm->name);
		}
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
		/* assert(ip->ip_ttl == 1); */
		assert(ip->ip_p == IPPROTO_PIM);
//		assert(!cksum(ip, ip->ip_hl << 2));
		assert(IN_MULTICAST(ntohl(ip->ip_dst.s_addr)));

		pim	= (struct pimhdr *) ((char *)buf + (ip->ip_hl << 2));

		assert(pim->ver == 2);
		assert(pim->reserved == 0);	/* TODO ignore */
//		assert(!cksum(pim, sizeof(struct pimhdr)));

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
		logger(LOG_WARNING, 0, "%s(): unknown socket type: %d", __func__, src_addr->ss_family);
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
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}

	return vif_add(sock, &ifctl);
}
