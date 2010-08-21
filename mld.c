#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/igmp.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pimky.h"

void mld_query_send(void)
{
	fprintf(stderr, "%d, sent igmp/mld query\n", (int) time(NULL));
}

void mld_recv(int sock, void *buf, int len,
		struct sockaddr *src_addr, socklen_t addrlen)
{
	struct iphdr	*ip;
	struct igmphdr	*igmp;

	printf("called %s\n", __func__);

	switch (src_addr->sa_family) {
	case AF_INET:
		ip	= (struct iphdr *) buf;

		assert(ip->version == 4);
		assert(ip->ihl >= 5);
		assert(ntohs(ip->tot_len) == len);
		/* TODO do we handle fragments? */
		assert(ntohs(ip->frag_off) == 0 || ntohs(ip->frag_off) & 0x4000);
		assert(ip->ttl == 1);
		assert(ip->protocol == IPPROTO_IGMP);
		assert(cksum(ip, ip->ihl << 2) == 0xffff);
		assert(IN_MULTICAST(ntohl(ip->daddr)));

		igmp	= (struct igmphdr *) ((char *)buf + (ip->ihl << 2));

		assert(cksum(igmp, sizeof(struct igmphdr)) == 0xffff);

		switch (igmp->type) {
		case IGMP_HOST_MEMBERSHIP_QUERY:
		case IGMP_HOST_MEMBERSHIP_REPORT:
		case IGMPV2_HOST_MEMBERSHIP_REPORT:
		case IGMP_HOST_LEAVE_MESSAGE:
		case IGMPV3_HOST_MEMBERSHIP_REPORT:
			break;
		default:
			printf("got unknown code %d\n", igmp->type);
		}

		break;
	case AF_INET6:
		break;
	default:
		logger(LOG_WARNING, 0, "%s(): unknown socket type: %d", __func__, src_addr->sa_family);
	}
}
