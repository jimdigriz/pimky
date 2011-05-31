/*
 * This file is part of:
 *	pimky - Slimline PIM Routing Daemon for IPv4 and IPv6
 * Copyright (C) 2010 - 2011  Alexander Clouter <alex@digriz.org.uk>
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

#define	VERSION				"2011053100"

#define	UID				"nobody"
#define	GID				"nogroup"

#define SOCK_BUFLEN			2048

extern int				debug;
extern unsigned int			running;
extern int				mroute4, mroute6;
extern int				pim4, pim6;
extern struct iface_map			iface_map;
extern struct iface_info		iface_info;

/* IANA address-family-numbers */
#define IANA_AFI_IPV4			1
#define IANA_AFI_IPV6			2

#define RFC3376_RFC3810_Query_Interval	125
#define RFC4601_Hello_Period		 30
#define RFC4601_Default_Hello_Holdtime	 (3.5 * RFC4601_Hello_Period)
#define RFC4601_Triggered_Hello_Delay	  5
#define RFC4601_Default_DR_Priority	  1

struct pimopt {
	uint16_t	type;
	uint16_t	len;

	union {
		uint16_t	holdtime;
		uint32_t	dr_priority;
		uint32_t	generation_id;
	} value;
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
	PIM_STATE_REFRESH,
	PIM_DF_ELECTION,
	/* unassigned */
	PIM_TYPE_EXT		= 15
};

enum {
	PIM_OPT_HOLDTIME	= 1,
	PIM_OPT_LAN_PRUNE_DELAY	= 2,
	PIM_OPT_DR_PRIORITY	= 19,
	PIM_OPT_GENERATION_ID	= 20,
	PIM_OPT_ADDRESS_LIST	= 24
};

/* RFC3228 section 4 */
enum {
	IGMP_MEMBER_QUERY	= 0x11,
	IGMPV1_MEMBER_REPORT	= 0x12,
	IGMPV2_MEMBER_REPORT	= 0x16,
	IGMPV2_LEAVE_GROUP	= 0x17,
	IGMPV3_MEMBER_REPORT	= 0x22
};

/* RFC3228 section 5 */
enum {
	MLD_LISTEN_QUERY	= 130,
	MLDV1_LISTEN_REPORT	= 131,
	MLDV1_LISTEN_DONE	= 132,
	MLDV2_LISTEN_REPORT	= 143
};

struct ip6_phdr {
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

union sockstore {
	struct sockaddr_storage	ss;
	struct sockaddr		sa;

	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};

struct pim_neigh {
	unsigned short		ipver;

	unsigned short		num_addr;
	union sockstore		*addr;

	uint32_t		dr_priority;
	uint32_t		generation_id;
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
		unsigned short	v4;
		unsigned short	v6;
	} ip;

	struct iface_info	*info;
};

struct iface_info {
	struct iface_info	*next;

	char			name[IFNAMSIZ];
	unsigned int		index;

	uint32_t		dr_priority;
	uint32_t		generation_id;

	struct iface_map	*map;
	struct pim_neigh	*pim_neigh;
};

/* utils.c */
void logger(int severity, int syserr, const char *format, ...);
ssize_t _recvfrom(int, void *, size_t, int,
		struct sockaddr *, socklen_t *);
ssize_t _sendto(int, const void *, size_t, int,
		const struct sockaddr *, socklen_t);
int socktype(int sock);
uint16_t in_cksum(const void *, int);
int family_to_level(int);
unsigned int genrand(unsigned int);

/* net.c */
int iface_info_glue(void);
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
int pim_hello_opt_add(unsigned char **, size_t, unsigned int,
		struct sockaddr_storage *, struct iface_map *);
void pim_hello_send(void);
void pim_recv(int, void *, int, struct sockaddr_storage *, socklen_t);
int pim_register(int);

/* mld.c */
void mld_query_send(void);
void mld_recv(int, void *, int, struct sockaddr_storage *, socklen_t);
