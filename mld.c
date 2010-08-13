#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pimky.h"

void mld_query_send(void)
{
	fprintf(stderr, "%d, sent igmp/mld query\n", (int) time(NULL));
}

void mld_recv(int sock, char *buf, int len, struct sockaddr *src_addr, socklen_t addrlen)
{
	printf("called %s\n", __func__);
}
