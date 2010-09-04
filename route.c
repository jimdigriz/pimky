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

#if defined(__linux__)
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#else
# error "no idea how to get routing/link information for your OS"
#endif

#include <arpa/inet.h>
#include <stdio.h>

#if defined(__linux__)
int rtnetlink_socket;
int rtnetlink_seq;

int route_init(void)
{
	struct sockaddr_nl sa;

	rtnetlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rtnetlink_socket < 0) {
		logger(LOG_ERR, errno, "socket(AF_NETLINK)");
		return -EX_OSERR;
	}

	memset(&sa, 0, sizeof(sa));

	sa.nl_family = AF_NETLINK;

	if (bind(rtnetlink_socket, (struct sockaddr *) &sa, sizeof(sa))) {
		logger(LOG_ERR, errno, "bind(AF_NETLINK)");
		close(rtnetlink_socket);
		return -EX_OSERR;
	}

	return EX_OK;
}

void route_shutdown(void)
{
	close(rtnetlink_socket);
}

int route_getsrc(int ifi, struct sockaddr_storage *dst, struct sockaddr_storage *src)
{
	struct {
		struct nlmsghdr	n;
		struct rtmsg	r;
		char		buf[1024];
	} req;
	struct rtattr		*rtatp;
	struct nlmsghdr		*nlmp;
	struct rtmsg		*rtmp;
	int			rtattrlen;
	union sockstore		*store;
	int			ret;
	char			buf[4096];

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len		= NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_type	= RTM_GETROUTE;
	req.n.nlmsg_flags	= NLM_F_REQUEST;
	req.n.nlmsg_seq		= rtnetlink_seq++;

	req.r.rtm_family	= dst->ss_family;
	req.r.rtm_table		= RT_TABLE_MAIN;

	rtatp = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
	rtatp->rta_type			= RTA_OIF;
	rtatp->rta_len			= RTA_LENGTH(sizeof(uint32_t));
	*((uint32_t *) RTA_DATA(rtatp))	= ifi;

	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(rtatp->rta_len);

	rtatp = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
	rtatp->rta_type			= RTA_DST;

	store = (union sockstore *) dst;
	switch (dst->ss_family) {
	case AF_INET:
		rtatp->rta_len = RTA_LENGTH(sizeof(struct in_addr));
		memcpy(RTA_DATA(rtatp), &store->s4.sin_addr, sizeof(struct in_addr));
		break;
	case AF_INET6:
		rtatp->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
		memcpy(RTA_DATA(rtatp), &store->s6.sin6_addr, sizeof(struct in6_addr));
		break;
	default:
		logger(LOG_ERR, 0, "%s(): unknown address type: %d", __func__, dst->ss_family);
		return -EX_SOFTWARE;
	}

	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(rtatp->rta_len);

	ret = _sendto(rtnetlink_socket, &req, req.n.nlmsg_len, 0, NULL, 0);
	if (ret == -1) {
		logger(LOG_ERR, errno, "unable to submit make routing query");
		goto exit;
	}

	ret = _recvfrom(rtnetlink_socket, buf, sizeof(buf), 0, NULL, 0);
	if (ret == -1) {
		logger(LOG_ERR, errno, "unable to receive routing response");
		goto exit;
	}

	nlmp 		= (struct nlmsghdr *) buf;

	rtmp		= (struct rtmsg *) NLMSG_DATA(nlmp);
	rtatp		= (struct rtattr *) RTM_RTA(rtmp);
	rtattrlen	= RTM_PAYLOAD (nlmp);

	ret = -EX_SOFTWARE;
	for (; RTA_OK(rtatp, rtattrlen); rtatp = RTA_NEXT(rtatp, rtattrlen)) {
		if (rtatp->rta_type == RTA_PREFSRC) {
			if (rtmp->rtm_type == RTN_UNREACHABLE) {
				src->ss_family = AF_UNSPEC;
				break;
			}

			store = (union sockstore *) src;
			switch (rtmp->rtm_family) {
			case AF_INET:
				store->s4.sin_addr.s_addr = ((struct in_addr *)RTA_DATA(rtatp))->s_addr;
				break;
			case AF_INET6:
				memcpy(&store->s6.sin6_addr, (struct in6_addr *)RTA_DATA(rtatp),
						sizeof(struct in6_addr));
				break;
			default:
				logger(LOG_ERR, 0, "kernel returned unknown address family: %d", rtmp->rtm_family);
				return ret;
			}

			src->ss_family = rtmp->rtm_family;
			ret = EX_OK;

			break;
		}
	}
exit:
	return ret;
}
#endif
