/*
 * This file is part of:
 * 	pimky - Slimline PIM Routing Daemon for IPv4 and IPv6
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

#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>

#if defined(__linux__)
#include <linux/mroute.h>
#include <linux/mroute6.h>
#elif defined(__APPLE__)
#include <netinet/ip_mroute.h>
#include <netinet6/ip6_mroute.h>
#endif

int pim_init(int sock)
{
	int			type;
	int			v = 1;
	int			ret;
	struct icmp6_filter	filter;
	int			pim;

	type = socktype(sock);
	if (type < 0)
		return type;

	switch (type) {
	case AF_INET:
		ret = setsockopt(sock, IPPROTO_IP, MRT_INIT, (void *)&v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_INIT)", __func__);
			return ret;
		}

#ifdef __linux__
		ret = setsockopt(sock, IPPROTO_IP, MRT_PIM, (void *)&v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_PIM)", __func__);
			return ret;
		}
#endif

		break;
	case AF_INET6:
		ret = setsockopt(sock, IPPROTO_IPV6, MRT6_INIT, (void *)&v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_INIT)", __func__);
			return ret;
		}

		ICMP6_FILTER_SETBLOCKALL(&filter);
		ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, (void *)&filter, sizeof(filter));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(ICMP6_FILTER)", __func__);
			return ret;
		}

		ret = setsockopt(sock, IPPROTO_IPV6, MRT6_PIM, (void *)&v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_PIM)", __func__);
			return ret;
		}

		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}

	pim = socket(type, SOCK_RAW, IPPROTO_PIM);
	if (pim < 0) {
		logger(LOG_ERR, errno, "%s(): socket(AF_INET, SOCK_RAW, IPPROTO_PIM)", __func__);
		return -EX_OSERR;
	}

	ret = pim_register(sock, type);

	return pim;
}

int pim_shutdown(int sock)
{
	int			type;
	int			v = 0;
	int			ret;

	type = socktype(sock);
	if (type < 0)
		return type;

	switch (type) {
	case AF_INET:
#ifdef __linux__
		ret = setsockopt(sock, IPPROTO_IP, MRT_PIM, (void *)&v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_PIM)", __func__);
			return ret;
		}
#endif

		ret = setsockopt(sock, IPPROTO_IP, MRT_DONE, (void *)NULL, 0);
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_INIT)", __func__);
			return ret;
		}

		break;
	case AF_INET6:
		ret = setsockopt(sock, IPPROTO_IPV6, MRT6_PIM, (void *)&v, sizeof(v));
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_PIM)", __func__);
			return ret;
		}

		ret = setsockopt(sock, IPPROTO_IPV6, MRT6_DONE, (void *)NULL, 0);
		if (ret < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_INIT)", __func__);
			return ret;
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
	fprintf(stderr, "sent pim hello\n");
}

void pim_recv(int sock, void *buf, int len,
		struct sockaddr *src_addr, socklen_t addrlen)
{
	struct iphdr	*ip;
	struct pimhdr	*pim;

	printf("called %s\n", __func__);

	switch (src_addr->sa_family) {
	case AF_INET:
		ip	= buf;

		assert(ip->version == 4);
		assert(ip->ihl >= 5);
		assert(ntohs(ip->tot_len) == len);
		/* TODO do we handle fragments? */
		assert(ntohs(ip->frag_off) == 0 || ntohs(ip->frag_off) & 0x4000);
		/* assert(ip->ttl == 1); */
		assert(ip->protocol == IPPROTO_PIM);
		assert(cksum(ip, ip->ihl << 2) == 0xffff);
		assert(IN_MULTICAST(ntohl(ip->daddr)));

		pim	= (struct pimhdr *) ((char *)buf + (ip->ihl << 2));

		assert(pim->ver == 2);
		assert(pim->reserved == 0);	/* TODO ignore */
		assert(cksum(pim, sizeof(struct pimhdr)) == 0xffff);

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
		logger(LOG_WARNING, 0, "%s(): unknown socket type: %d", __func__, src_addr->sa_family);
	}
}

int pim_register(int sock, int type)
{
	struct pimky_ifctl	ifctl;
	struct sockaddr_storage	addr;
	int 			ret = EX_OK;

	memset(&ifctl, 0, sizeof(struct pimky_ifctl));
	memset(&addr, 0, sizeof(struct sockaddr_storage));

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

	ret = vif_add(sock, type, &ifctl);
	if (!ret) {
		addr.ss_family = type;
		ret = mcast_add(sock, &addr);
	}

	return ret;
}
