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

#include "pimky.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

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
		buf = realloc(buf, bufsize);
		if (buf == NULL) {
			syslog(LOG_CRIT, "realloc() for syslog");
			goto free;
		}

		ret = vsnprintf(buf, bufsize, format, ap);
		if (ret < 0) {
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

int socktype(int sock)
{
	struct sockaddr	addr;
	socklen_t	len = sizeof(addr);

	if (getsockname(sock, &addr, &len) < 0) {
		logger(LOG_ERR, errno, "getsockname()");
		return -EX_OSERR;
	}

	return addr.sa_family;
}

/* when checking, pass header and check for return of 0xffff (~0)*/
uint16_t cksum(void *buf, int len)
{
	uint16_t	*b	= buf;
	unsigned int	sum	= 0;

	for (; b < (uint16_t *) ((char *)buf + len); b++)
		sum += *b;

	sum = (sum & 0xffff) >> 16;
	sum = ~sum;

	return sum;
}

int family_to_level(int type)
{
	switch (type) {
	case AF_INET:
		return IPPROTO_IP;
	case AF_INET6:
		return IPPROTO_IPV6;
	default:
		logger(LOG_ERR, 0, "%s(): unknown socket type: %d", __func__, type);
		return -EX_SOFTWARE;
	}
}
