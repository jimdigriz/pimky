#define	VERSION "2010081100"

#define	UID	"nobody"
#define	GID	"nogroup"

/* defaults */
extern int		debug;
extern unsigned int	nofork;
extern char		*uid;
extern char		*gid;

#define RFC3376_RFC3810_Query_Interval	125
#define RFC4601_Hello_Period		 30
#define RFC4601_Triggered_Hello_Delay	  5

/* utils.c */
void logger(int severity, int syserr, const char *format, ...);
int socktype(int sock);

/* pim.c */
int pim_init(int sock);
int pim_shutdown(int sock);
void pim_hello_send();

/* mld.c */
void mld_query_send();
