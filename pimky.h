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

#include <syslog.h>
#include <sysexits.h>
#include <errno.h>
#include <assert.h>

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#define	VERSION		"2010081100"

#define	UID		"nobody"
#define	GID		"nogroup"

#define SOCK_BUFLEN	2048

extern int		debug;
extern int		mroute4, mroute6;
extern int		pim4, pim6;
extern struct iface_map	iface_map;

#define RFC3376_RFC3810_Query_Interval	125
#define RFC4601_Hello_Period		 30
#define RFC4601_Default_Hello_Holdtime	(3.5 * RFC4601_Hello_Period)
#define RFC4601_Triggered_Hello_Delay	  5

struct pimopt {
	uint16_t	type;
	uint16_t	len;

	union {
		uint16_t	holdtime;
	} payload;
} __attribute__((__packed__));

struct pimhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int	type:4;
	unsigned int	ver:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int	ver:4;
	unsigned int	type:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t		reserved;
	uint16_t	cksum;
} __attribute__((__packed__));

/* RFC4601 section 4.9 */
enum {
	PIM_HELLO		= 0,
	PIM_REGISTER,
	PIM_REGISTER_STOP,
	PIM_JOIN_PRUNE,
	PIM_BOOTSTRAP,
	PIM_ASSERT,
	PIM_GRAFT,
	PIM_GRAFT_ACK,
	PIM_CAND_RP_ADVERT,
	PIM_STATE_REFRESH
};

enum {
	PIM_OPT_HOLDTIME	= 1
};

struct ip6_pseudohdr {
	struct in6_addr	src;
	struct in6_addr	dst;
	uint32_t	len;
	uint8_t		zero[3];
	uint8_t		nexthdr;
} __attribute__((__packed__));

/* mroute.h/mroute6.h combined */
struct pimky_ifctl {
	unsigned short	ifi;
	unsigned char	flags;
	unsigned char	threshold;
};

struct iface_map_addr {
	struct iface_map_addr	*next;

	unsigned int		flags;
	struct sockaddr_storage	addr;
	struct sockaddr_storage	netmask;
	union {
		struct sockaddr_storage	broadaddr;
		struct sockaddr_storage	dstaddr;
	} ifu;
};

struct iface_map {
	struct iface_map	*next;

	char			name[IFNAMSIZ];
	unsigned int		index;
	unsigned int		flags;
	struct iface_map_addr	*addr;

	struct {
		unsigned int	v4:1;
		unsigned int	v6:1;
	} ip;
};

union sockstore {
	struct sockaddr_storage	ss;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};

/* utils.c */
void logger(int severity, int syserr, const char *format, ...);
ssize_t _recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t _sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
int socktype(int sock);
uint16_t in_cksum(const void *, int);
int family_to_level(int);

/* net.c */
void iface_map_init(void);
int iface_map_get(void);
int mcast_join(int, int, struct sockaddr_storage *);
int vif_add(int, struct pimky_ifctl *);

/* route.c */
int route_init(void);
void route_shutdown(void);
int route_getsrc(int, struct sockaddr_storage *, struct sockaddr_storage *);

/* pim.c */
int pim_init(int);
int pim_shutdown(int);
void pim_hello_send(void);
void pim_recv(int, void *, int, struct sockaddr_storage *, socklen_t);
int pim_register(int);

/* mld.c */
void mld_query_send(void);
void mld_recv(int, void *, int, struct sockaddr_storage *, socklen_t);
