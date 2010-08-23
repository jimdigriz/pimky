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
#include <netinet/igmp.h>

void mld_query_send(void)
{
	fprintf(stderr, "sent igmp/mld query\n");
}

void mld_recv(int sock, void *buf, int len,
		struct sockaddr *src_addr, socklen_t addrlen)
{
	struct ip	*ip;
	struct igmp	*igmp;

	printf("called %s\n", __func__);

	switch (src_addr->sa_family) {
	case AF_INET:
		ip	= buf;

		assert(ip->ip_v == 4);
		assert(ip->ip_hl >= 5);
		assert(ntohs(ip->ip_len) == len);
		/* TODO do we handle fragments? */
		assert(ntohs(ip->ip_off) & IP_OFFMASK == 0
				&& ntohs(ip->ip_off) & (~IP_OFFMASK) != IP_MF);
		assert(ip->ip_ttl == 1);
		assert(ip->ip_p == IPPROTO_IGMP);
		assert(cksum(ip, ip->ip_hl << 2) == 0xffff);
		assert(IN_MULTICAST(ntohl(ip->ip_dst)));

		igmp	= (struct igmp *) ((char *)buf + (ip->ip_hl << 2));

		assert(cksum(igmp, sizeof(struct igmp)) == 0xffff);

		switch (igmp->igmp_type) {
		default:
			printf("got unknown code %d\n", igmp->igmp_type);
		}

		break;
	case AF_INET6:
		break;
	default:
		logger(LOG_WARNING, 0, "%s(): unknown socket type: %d", __func__, src_addr->sa_family);
	}
}
