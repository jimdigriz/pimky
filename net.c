#include <syslog.h>
#include <sysexits.h>
#include <errno.h>

#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if.h>
#include <string.h>

#include "pimky.h"

void iface_map_free(struct iface_map *iface_map)
{
	struct iface_map *ifm;

	for (ifm = iface_map; ifm != NULL; ifm = &ifm[1]) {
		free(ifm->addr);
		if (!(ifm->flags & IFF_LOOPBACK))
			break;
	}

	free(iface_map);
	iface_map = NULL;
}

int iface_map_get(struct iface_map **iface_map)
{
	struct ifaddrs *ifaddr, *ifa;
	struct iface_map_addr *ifma;
	struct iface_map *ifm;
	int ifindex, i, j;
	int ret = EX_OK;

	iface_map_free(*iface_map);

	if(getifaddrs(&ifaddr)) {
		logger(LOG_ERR, errno, "getifaddrs()");
		ret = -EX_OSERR;
		goto exit;
	}

	i = 0;
	for (ifa = ifaddr; ifa->ifa_next != NULL; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & (IFF_UP | IFF_MULTICAST)))
			continue;

		if (ifa->ifa_flags & (IFF_LOOPBACK | IFF_SLAVE))
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET
				&& ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		ifindex = if_nametoindex(ifa->ifa_name);
		assert(ifindex);

		for (ifm = *iface_map; ifm != NULL; ifm = &ifm[1]) {
			if (ifm->index == ifindex)
				break;
			if (!(ifm->flags & IFF_LOOPBACK)) {
				ifm = NULL;
				break;
			}
		}
		if (!ifm) {
			*iface_map = realloc(*iface_map, (i+1)*sizeof(struct iface_map));
			if (!*iface_map) {
				logger(LOG_ERR, errno, "realloc()");
				ret = -EX_OSERR;
				iface_map_free(*iface_map);
				goto ifaddrs;
			}
			ifm = &(*iface_map)[i];
			memset(ifm, 0, sizeof(struct iface_map));

			if (i > 0)
				ifm[-1].flags |= IFF_LOOPBACK;

			ifm->index	= ifindex;
			ifm->flags	= ifa->ifa_flags;
			strncpy(ifm->name, ifa->ifa_name, IFNAMSIZ);

			i++;
		}

		j = 0;
		for (ifma = ifm->addr; ifma != NULL; ifma = &ifma[1]) {
			j++;
			if (!(ifma->flags & IFF_LOOPBACK))
				break;
		}
		ifm->addr = realloc(ifm->addr, (j+1)*sizeof(struct iface_map_addr));
		if (!ifm->addr) {
			logger(LOG_ERR, errno, "realloc()");
			ret = -EX_OSERR;
			iface_map_free(*iface_map);
			goto ifaddrs;
		}
		ifma = &ifm->addr[j];
		memset(ifma, 0, sizeof(struct iface_map_addr));

		if (j > 0)
			ifma[-1].flags |= IFF_LOOPBACK;

		ifma->flags = ifa->ifa_flags;
		/* I assume the following always holds true */
		assert((ifm->flags | IFF_LOOPBACK) == (ifma->flags | IFF_LOOPBACK));

		memcpy(&ifma->addr, ifa->ifa_addr, sizeof(struct sockaddr));
		if (ifa->ifa_netmask)
			memcpy(&ifma->netmask, ifa->ifa_netmask, sizeof(struct sockaddr));
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			memcpy(&ifma->ifu.dstaddr,
					ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr));
		else if (ifa->ifa_flags & IFF_BROADCAST && ifa->ifa_ifu.ifu_broadaddr)
			memcpy(&ifma->ifu.broadaddr,
					ifa->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr));
	}

ifaddrs:
	freeifaddrs(ifaddr);
exit:
	return ret;
}
