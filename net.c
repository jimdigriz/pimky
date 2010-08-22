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
	struct iface_map *ifm, *nifm;
	struct iface_map_addr *ifma, *nifma;

	ifm = iface_map;
	while (ifm != NULL) {
		nifm = ifm->next;

		ifma = iface_map->addr;
		while (ifma != NULL) {
			nifma = ifma->next;
			free(ifma);
			ifma = nifma;
		}

		free(ifm);
		ifm = nifm;
	}
}

int iface_map_get(struct iface_map **iface_map)
{
	struct ifaddrs *ifaddr, *ifa;
	struct iface_map_addr *ifma;
	struct iface_map *ifm;
	int ifindex;
	int ret = EX_OK;

	iface_map_free(*iface_map);

	/* dummy entry */
	*iface_map = malloc(sizeof(struct iface_map));
	if (*iface_map == NULL) {
		logger(LOG_ERR, errno, "malloc(iface_map - dummy)");
		ret = -EX_OSERR;
		goto exit;
	}
	memset(*iface_map, 0, sizeof(struct iface_map));

	if(getifaddrs(&ifaddr)) {
		logger(LOG_ERR, errno, "getifaddrs()");
		ret = -EX_OSERR;
		goto exit;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & (IFF_UP | IFF_MULTICAST)))
			continue;

		if (ifa->ifa_flags & (IFF_LOOPBACK | IFF_SLAVE))
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET
				&& ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		ifindex = if_nametoindex(ifa->ifa_name);
		assert(ifindex);

		for (ifm = *iface_map; ifm != NULL; ifm = ifm->next)
			if (ifm->index == ifindex)
				break;
		if (ifm == NULL) {
			ifm = malloc(sizeof(struct iface_map));
			if (ifm == NULL) {
				logger(LOG_ERR, errno, "malloc(iface_map)");
				ret = -EX_OSERR;
				iface_map_free(*iface_map);
				goto ifaddrs;
			}
			memset(ifm, 0, sizeof(struct iface_map));

			ifm->next		= (*iface_map)->next;
			(*iface_map)->next	= ifm;

			ifm->index		= ifindex;
			ifm->flags		= ifa->ifa_flags;
			strncpy(ifm->name, ifa->ifa_name, IFNAMSIZ);

			/* dummy entry */
			ifm->addr = malloc(sizeof(struct iface_map_addr));
			if (ifm->addr == NULL) {
				logger(LOG_ERR, errno, "malloc(iface_map_addr - dummy)");
				ret = -EX_OSERR;
				iface_map_free(*iface_map);
				goto ifaddrs;
			}
			memset(ifm->addr, 0, sizeof(struct iface_map_addr));
		}

		ifma = malloc(sizeof(struct iface_map_addr));
		if (ifma == NULL) {
			logger(LOG_ERR, errno, "alloc(iface_map_addr)");
			ret = -EX_OSERR;
			iface_map_free(*iface_map);
			goto ifaddrs;
		}
		memset(ifma, 0, sizeof(struct iface_map_addr));

		ifma->next	= ifm->addr->next;
		ifm->addr->next	= ifma;

		ifma->flags 	= ifa->ifa_flags;
		/* I assume the following always holds true */
		assert(ifm->flags == ifma->flags);

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
