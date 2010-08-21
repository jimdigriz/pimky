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

int iface_map_get(struct iface_map *iface_map)
{
	struct ifaddrs *ifaddr, *ifa;
	int i = 0;
	int ret = EX_OK;

	if(getifaddrs(&ifaddr)) {
		logger(LOG_ERR, errno, "getifaddrs()");
		ret = -EX_OSERR;
		goto exit;
	}

	free(iface_map);

	for (ifa = ifaddr; ifa->ifa_next != NULL; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & (IFF_UP | IFF_MULTICAST)))
			continue;

		if (ifa->ifa_flags & (IFF_LOOPBACK | IFF_SLAVE))
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET
				&& ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		iface_map = realloc(iface_map, (i+1)*sizeof(struct iface_map));
		if (!iface_map) {
			logger(LOG_ERR, errno, "realloc()");
			ret = -EX_OSERR;
			free(iface_map);
			goto ifaddrs;
		}
		/* memset(iface_map[i], 0, sizeof(struct iface_map)); */

		iface_map[i].index	= if_nametoindex(ifa->ifa_name);
		assert(iface_map[i].index);
		iface_map[i].flags	= ifa->ifa_flags;

		strncpy(iface_map[i].name, ifa->ifa_name, IFNAMSIZ);
		memcpy(&iface_map[i].addr, ifa->ifa_addr, sizeof(struct sockaddr));

		if (ifa->ifa_netmask)
			memcpy(&iface_map[i].netmask, ifa->ifa_netmask, sizeof(struct sockaddr));

		if (ifa->ifa_flags & IFF_POINTOPOINT)
			memcpy(&iface_map[i].ifu.dstaddr, ifa->ifa_ifu.ifu_dstaddr, sizeof(struct sockaddr));
		else if (ifa->ifa_flags & IFF_BROADCAST && ifa->ifa_ifu.ifu_broadaddr)
			memcpy(&iface_map[i].ifu.broadaddr, ifa->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr));

		i++;
	}

ifaddrs:
	freeifaddrs(ifaddr);
exit:
	return ret;
}


