#include <stdint.h>
#include <netinet/in.h>
#include <linux/if.h>

#define	VERSION		"2010081100"

#define	UID		"nobody"
#define	GID		"nogroup"

#define SOCK_BUFLEN	2048

/* defaults */
extern int		debug;
extern unsigned int	nofork;
extern char		*uid;
extern char		*gid;

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
	PIM_CAND_RP_ADVERT,
};

/*
 * these two following structure would normally have a *next entry however
 * as we use realloc() to build them we would have to reglue the struct after
 * each call to realloc().  Instead we use a flag to indicate if there are
 * further entries in the array, fortunately we can cheat and use IFF_LOOPBACK
 * as it is not needed for multicast.
 *
 * N.B. chosen to avoid lots of small malloc()'s and free()'ing much simpler
 */
#define	IFACE_MAP_CONT	IFF_LOOPBACK

struct iface_map_addr {
	unsigned int		flags;
	struct sockaddr		addr;
	struct sockaddr		netmask;
	union {
		struct sockaddr	broadaddr;
		struct sockaddr	dstaddr;
	} ifu;
};

struct iface_map {
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
void iface_map_free(struct iface_map *);
int iface_map_get(struct iface_map **);

/* pim.c */
int pim_init(int);
int pim_shutdown(int);
void pim_hello_send(void);
void pim_recv(int, void *, int, struct sockaddr *, socklen_t);

/* mld.c */
void mld_query_send(void);
void mld_recv(int, void *, int, struct sockaddr *, socklen_t);
