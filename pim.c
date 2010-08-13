#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>

#include "pimky.h"

int pim_init(int sock)
{
	int			type;
	int			v = 1;
	int			ret;
	struct icmp6_filter	filter;
	int			pim;

	if ((type = socktype(sock)) < 0)
		return type;

	switch (type) {
	case AF_INET:
		if ((ret = setsockopt(sock, IPPROTO_IP, MRT_INIT, (void *)&v, sizeof(v))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_INIT)", __func__);
			return ret;
		}

		if ((ret = setsockopt(sock, IPPROTO_IP, MRT_PIM, (void *)&v, sizeof(v))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_PIM)", __func__);
			return ret;
		}

		break;
	case AF_INET6:
		if ((ret = setsockopt(sock, IPPROTO_IPV6, MRT6_INIT, (void *)&v, sizeof(v))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_INIT)", __func__);
			return ret;
		}

		ICMP6_FILTER_SETBLOCKALL(&filter);
		if ((ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, (void *)&filter, sizeof(filter))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(ICMP6_FILTER)", __func__);
			return ret;
		}

		if ((ret = setsockopt(sock, IPPROTO_IPV6, MRT6_PIM, (void *)&v, sizeof(v))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_PIM)", __func__);
			return ret;
		}

		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}

	if ((pim = socket(type, SOCK_RAW, IPPROTO_PIM)) < 0) {
		logger(LOG_ERR, errno, "%s(): socket(AF_INET, SOCK_RAW, IPPROTO_PIM)", __func__);
		return -EX_OSERR;
	}

	return pim;
}

int pim_shutdown(int sock)
{
	int			type;
	int			v = 0;
	int			ret;

	if ((type = socktype(sock)) < 0)
		return type;

	switch (type) {
	case AF_INET:
		if ((ret = setsockopt(sock, IPPROTO_IP, MRT_PIM, (void *)&v, sizeof(v))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_PIM)", __func__);
			return ret;
		}

		if ((ret = setsockopt(sock, IPPROTO_IP, MRT_DONE, (void *)NULL, 0)) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT_INIT)", __func__);
			return ret;
		}

		break;
	case AF_INET6:
		if ((ret = setsockopt(sock, IPPROTO_IPV6, MRT6_PIM, (void *)&v, sizeof(v))) < 0) {
			logger(LOG_ERR, errno, "%s(): setsockopt(MRT6_PIM)", __func__);
			return ret;
		}

		if ((ret = setsockopt(sock, IPPROTO_IPV6, MRT6_DONE, (void *)NULL, 0)) < 0) {
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
	fprintf(stderr, "%d, sent pim hello\n", (int) time(NULL));
}

void pim_recv(int sock, char *buf, int len, struct sockaddr *src_addr, socklen_t addrlen)
{
	printf("called %s\n", __func__);
}
