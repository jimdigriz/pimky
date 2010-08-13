#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>
#include <sys/socket.h>

#include "pimky.h"

void logger(int severity, int syserr, const char *format, ...)
{
	va_list	ap;
	char	*buf	= NULL;
	int	bufsize	= 4096;
	int	ret;

	if (debug < severity)
		return;

	va_start(ap, format);

	while (1) {
		if (!(buf = realloc(buf, bufsize))) {
			syslog(LOG_CRIT, "realloc() for syslog");
			goto free;
		}

		if ((ret = vsnprintf(buf, bufsize, format, ap)) < 0 ) {
			syslog(LOG_CRIT, "vsnprintf() for syslog");
			goto free;
		}

		if (ret < bufsize)
			break;

		bufsize += 4096;
	}

	if (syserr)
		syslog(severity, "%s: %s", buf, strerror(syserr));
	else
		syslog(severity, buf);

free:
	free(buf);
	va_end(ap);
}

int socktype(int sock) {
	struct sockaddr	addr;
	socklen_t	len = sizeof(addr);

	if (getsockname(sock, &addr, &len) < 0) {
		logger(LOG_ERR, errno, "getsockname()");
		return -EX_OSERR;
	}

	return addr.sa_family;
}
