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
#define RFC4601_Triggered_Hello_Delay	  5

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
	uint16_t	check;
};

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
	PIM_CAND_RP_ADVERT
};

/* mroute.h/mroute6.h combined */
struct pimky_ifctl {
	unsigned short	ifi;
	unsigned char	flags;
};

struct iface_map_addr {
	struct iface_map_addr	*next;

	unsigned int		flags;
	struct sockaddr		addr;
	struct sockaddr		netmask;
	union {
		struct sockaddr	broadaddr;
		struct sockaddr	dstaddr;
	} ifu;
};

struct iface_map {
	struct iface_map	*next;

	char			name[IFNAMSIZ];
	unsigned int		index;
	unsigned int		flags;
	struct iface_map_addr	*addr;
};

/* utils.c */
void logger(int severity, int syserr, const char *format, ...);
int socktype(int sock);
uint16_t cksum(void *, int);

/* net.c */
void iface_map_init(void);
int iface_map_get(void);
int mcast_add(int, struct sockaddr_storage *);
int vif_add(int, int, struct pimky_ifctl *);

/* pim.c */
int pim_init(int);
int pim_shutdown(int);
void pim_hello_send(void);
void pim_recv(int, void *, int, struct sockaddr *, socklen_t);
int pim_register(int, int);

/* mld.c */
void mld_query_send(void);
void mld_recv(int, void *, int, struct sockaddr *, socklen_t);
