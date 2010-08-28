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

#include <stdlib.h>
#include <string.h>
/* uClibc: UCLIBC_USE_NETLINK && UCLIBC_SUPPORT_AI_ADDRCONFIG */
#include <ifaddrs.h>

#if defined(__linux__)
#include <linux/mroute.h>
#include <linux/mroute6.h>
#elif defined(__FreeBSD__)
#include <netinet/ip_mroute.h>
#include <netinet6/ip6_mroute.h>
#endif

void iface_map_init(void)
{
	struct iface_map *ifm, *nifm;
	struct iface_map_addr *ifma, *nifma;

	ifm = iface_map.next;
	while (ifm != NULL) {
		nifm = ifm->next;

		ifma = ifm->addr;
		while (ifma != NULL) {
			nifma = ifma->next;
			free(ifma);
			ifma = nifma;
		}

		free(ifm);
		ifm = nifm;
	}

	memset(&iface_map, 0, sizeof(struct iface_map));
}

int iface_map_get(void)
{
	struct ifaddrs *ifaddr, *ifa;
	struct iface_map_addr *ifma;
	struct iface_map *ifm;
	int ifindex;
	int cifv4 = 0, cifv6 = 0;
	int ret = EX_OK;

	iface_map_init();

	if(getifaddrs(&ifaddr)) {
		logger(LOG_ERR, errno, "getifaddrs()");
		ret = -EX_OSERR;
		goto exit;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & (IFF_UP | IFF_MULTICAST)))
			continue;

		if (ifa->ifa_flags & IFF_LOOPBACK)
			continue;

#ifdef __linux__
		if (ifa->ifa_flags & IFF_SLAVE)
			continue;
#endif

		/* BSD populates struct per interface, not per address */
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET
				&& ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		if (mroute4 < 0 && ifa->ifa_addr->sa_family == AF_INET)
			continue;
		if (mroute6 < 0 && ifa->ifa_addr->sa_family == AF_INET6)
			continue;

		ifindex = if_nametoindex(ifa->ifa_name);
		assert(ifindex);

		for (ifm = iface_map.next; ifm != NULL; ifm = ifm->next)
			if (ifm->index == ifindex)
				break;
		if (ifm == NULL) {
			ifm = malloc(sizeof(struct iface_map));
			if (ifm == NULL) {
				logger(LOG_ERR, errno, "malloc(iface_map)");
				ret = -EX_OSERR;
				iface_map_init();
				goto ifaddrs;
			}
			memset(ifm, 0, sizeof(struct iface_map));

			ifm->next	= iface_map.next;
			iface_map.next	= ifm;

			ifm->index	= ifindex;
			ifm->flags	= ifa->ifa_flags;
			strncpy(ifm->name, ifa->ifa_name, IFNAMSIZ);

			/* dummy entry */
			ifm->addr = malloc(sizeof(struct iface_map_addr));
			if (ifm->addr == NULL) {
				logger(LOG_ERR, errno, "malloc(iface_map_addr - dummy)");
				ret = -EX_OSERR;
				iface_map_init();
				goto ifaddrs;
			}
			memset(ifm->addr, 0, sizeof(struct iface_map_addr));
		}

		ifma = malloc(sizeof(struct iface_map_addr));
		if (ifma == NULL) {
			logger(LOG_ERR, errno, "alloc(iface_map_addr)");
			ret = -EX_OSERR;
			iface_map_init();
			goto ifaddrs;
		}
		memset(ifma, 0, sizeof(struct iface_map_addr));

		ifma->next	= ifm->addr->next;
		ifm->addr->next	= ifma;

		ifma->flags 	= ifa->ifa_flags;
		/* I assume the following always holds true */
		assert(ifm->flags == ifma->flags);

		memcpy(&ifma->addr, ifa->ifa_addr, sizeof(ifma->addr));
		if (ifa->ifa_netmask)
			memcpy(&ifma->netmask, ifa->ifa_netmask, sizeof(ifma->netmask));
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			memcpy(&ifma->ifu.dstaddr, ifa->ifa_dstaddr, sizeof(ifma->ifu.dstaddr));
		else if (ifa->ifa_flags & IFF_BROADCAST && ifa->ifa_broadaddr)
			memcpy(&ifma->ifu.broadaddr, ifa->ifa_broadaddr, sizeof(ifma->ifu.broadaddr));
	}

	/* check we are not exceeding MAXVIFS or MAXMIFS */
	for (ifm = iface_map.next; ifm != NULL; ifm = ifm->next) {
		for (ifma = ifm->addr->next; ifma != NULL; ifma = ifma->next)
			if (ifma->addr.ss_family == AF_INET) {
				cifv4++;
				break;
			}
		for (ifma = ifm->addr->next; ifma != NULL; ifma = ifma->next)
			if (ifma->addr.ss_family == AF_INET6) {
				cifv6++;
				break;
			}
	}
	/* one short as we need space for vif0 */
	assert(cifv4 < MAXVIFS - 1);
	assert(cifv6 < MAXMIFS - 1);

ifaddrs:
	freeifaddrs(ifaddr);
exit:
	return ret;
}

int mcast_add(int sock, struct sockaddr_storage *addr)
{
	union {
		struct ip_mreq		v4;
		struct ipv6_mreq	v6;
	} mreq;

	memset(&mreq, 0, sizeof(mreq));

	switch (addr->ss_family) {
	case AF_INET:
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(IP_ADD_MEMBERSHIP)", __func__);
			return -EX_OSERR;
		}
		break;
	case AF_INET6:
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(IPV6_JOIN_GROUP)", __func__);
			return -EX_OSERR;
		}
		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, addr->ss_family);
		return -EX_SOFTWARE;
	}

	return EX_OK;
}

int vif_add(int sock, int type, struct pimky_ifctl *ifctl)
{
	union {
		struct vifctl	v4;
		struct mif6ctl	v6;
	} mif;

	memset(&mif, 0, sizeof(mif));

	switch (type) {
	case AF_INET:
		mif.v4.vifc_vifi	= ifctl->ifi;
		mif.v4.vifc_flags	= ifctl->flags;

		if (setsockopt(sock, IPPROTO_IP, MRT_ADD_VIF, &mif, sizeof(mif)) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_ADD_VIF)", __func__);
			return -EX_OSERR;
		}
		break;
	case AF_INET6:
		mif.v6.mif6c_mifi	= ifctl->ifi;
		mif.v6.mif6c_flags	= ifctl->flags;

		if (setsockopt(sock, IPPROTO_IPV6, MRT6_ADD_MIF, &mif, sizeof(mif)) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_ADD_MIF)", __func__);
			return -EX_OSERR;
		}
		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}

	return EX_OK;
}
