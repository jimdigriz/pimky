/*
 * pimky - Slimline PIM Routing Daemon for IPv4 and IPv6
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

/* http://tools.ietf.org/html/rfc4601 - pim */
/* http://tools.ietf.org/html/rfc5059 - pim-ssm */

/* http://tools.ietf.org/html/rfc3376 - igmpv3 */
/* http://tools.ietf.org/html/rfc3810 - mld */
/* http://tools.ietf.org/html/rfc4604 - igmpv3/mld-ssm */

#include "pimky.h"

#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

unsigned int		nofork;	/* zero */
char			*uid	= UID;
char			*gid	= GID;

unsigned int		running	= 1;

int			mroute4, mroute6;
int			pim4, pim6;
struct iface_map	iface_map;
struct iface_info	iface_info;

/* http://www.gnu.org/s/libc/manual/html_node/Getopt.html */
int parse_args(int argc, char **argv)
{
	int c;

	opterr = 0;

	while ((c = getopt(argc, argv, "nu:g:vqVh")) != -1)
	switch (c) {
	case 'n':
		nofork = 1;
		break;
	case 'u':
		uid = optarg;
		break;
	case 'g':
		gid = optarg;
		break;
	case 'v':
		debug++;
		break;
	case 'q':
		debug--;
		break;
	case '?':
		if (optopt == 'u' || optopt == 'g')
			fprintf(stderr, "option -%c requires an argument.\n",
					optopt);
		else if (isprint(optopt))
			fprintf(stderr, "unknown option `-%c'.\n", optopt);
		else
			fprintf(stderr, "unknown option character `\\x%x'.\n",
					optopt);
		return -EX_USAGE;
	case 'V':
		printf("%s %s\n\n", basename(argv[0]), VERSION);
		printf("Copyright (C) 2010 - 2011  Alexander Clouter <alex@digriz.org.uk>\n"
			"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
			"This is free software: you are free to change and redistribute it.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n");
		return -EX_SOFTWARE;
	case 'h':
	default:
		printf("Usage: %s [-h] [-V] [options] [(-q|-v)]\n",
				basename(argv[0]));
		printf("Slimline PIM Routing Daemon for IPv4 and IPv6\n"
			"\n"
			"  -n		do not fork (additionally logs to stderr)\n"
			"  -u name	drop privileges to user (default: '%s')\n"
			"  -g name	drop privileges to group (default: '%s')\n"
			"\n"
			"  -q		be quieter\n"
			"  -v		be more verbose\n"
			"\n"
			"  -h		display this help and exit\n"
			"  -V		print version information and exit\n", UID, GID);
		return -EX_SOFTWARE;
	}

	if (optind != argc) {
		fprintf(stderr, "we do not accept any arguments\n");
		return -EX_USAGE;
	}
	/* for (index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]); */

	if (debug < LOG_EMERG)
		debug = LOG_EMERG;
	else if (debug > LOG_DEBUG)
		debug = LOG_DEBUG;

	return EX_OK;
}

int signals(void (*handler)(int))
{
	int ret;
	struct sigaction action;

	action.sa_handler	= handler;
	action.sa_flags		= 0;

	sigemptyset(&action.sa_mask);

	ret = sigaction(SIGTERM, &action, NULL);
	if (ret)
		goto err;
	ret = sigaction(SIGTERM, &action, NULL);
	if (ret)
		goto err;
	ret = sigaction(SIGINT,  &action, NULL);
	if (ret)
		goto err;
	ret = sigaction(SIGUSR1, &action, NULL);
	if (ret)
		goto err;
	ret = sigaction(SIGUSR2, &action, NULL);
	if (ret)
		goto err;

	return EX_OK;

err:
	logger(LOG_ERR, errno, "unable to sigaction() all signals");
	return -EX_OSERR;
}

void sig_handler(int sig)
{
	int ret;

	if (sig == SIGUSR1) {
		mld_query_send();
		return;
	}
	if (sig == SIGUSR2) {
		ret = iface_map_get();
		if (ret < 0)
			goto exit;

		ret = iface_info_glue();
		if (ret < 0)
			goto exit;

		pim_hello_send();
		return;
	}

exit:
	running = 0;
	signals(SIG_IGN);
	pim_hello_send();
}

int prime_timers(timer_t *mld, timer_t *pim)
{
	struct itimerspec	timer;
	struct sigevent		event;

	event.sigev_notify	= SIGEV_SIGNAL;

	event.sigev_signo	= SIGUSR1;
	if (timer_create(CLOCK_MONOTONIC, &event, mld)) {
		logger(LOG_ERR, errno, "timer_create(mld)");
		return -EX_OSERR;
	}
	timer.it_value.tv_sec		= RFC3376_RFC3810_Query_Interval;
	timer.it_value.tv_nsec		= 0;
	timer.it_interval.tv_sec	= RFC3376_RFC3810_Query_Interval;
	timer.it_interval.tv_nsec	= 0;
	if (timer_settime(*mld, 0, &timer, NULL)) {
		logger(LOG_ERR, errno, "timer_settime(mld)");
		goto mld;
	}

	event.sigev_signo	= SIGUSR2;
	if (timer_create(CLOCK_MONOTONIC, &event, pim)) {
		logger(LOG_ERR, errno, "timer_create(pim)");
		goto mld;
	}

	timer.it_value.tv_nsec		= genrand(RFC4601_Triggered_Hello_Delay * (int) 1e6);

	timer.it_value.tv_sec		= (time_t) timer.it_value.tv_nsec / 1e6;
	timer.it_value.tv_nsec		= timer.it_value.tv_nsec % (int) 1e6;
	timer.it_interval.tv_sec	= RFC4601_Hello_Period;
	timer.it_interval.tv_nsec	= 0;
	if (timer_settime(*pim, 0, &timer, NULL)) {
		logger(LOG_ERR, errno, "timer_settime(pim)");
		goto pim;
	}

	return EX_OK;

pim:
	timer_delete(*pim);
mld:
	timer_delete(*mld);
	return -EX_OSERR;
}

void add_poll(struct pollfd *fds, nfds_t *nfds, int fd)
{
	fds[*nfds].fd		= fd;
	fds[*nfds].events	= POLLIN | POLLERR | POLLHUP;

	(*nfds)++;
}

int main(int argc, char **argv)
{
	int			ret = EX_OK;
	int			i;
	struct group		*grgid;
	struct passwd		*pwuid;
	timer_t			timerid_mld, timerid_pim;
	struct pollfd		fds[4];
	nfds_t			nfds = 0;
	struct sockaddr_storage	src_addr;
	socklen_t		addrlen = sizeof(src_addr);
	char			*buf;

	ret = parse_args(argc, argv);
	if (ret)
		return -ret;

	if (getuid()) {
		fprintf(stderr, "need to run as root\n");
		return EX_NOPERM;
	}

	if (!nofork) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork()");
			return EX_OSERR;
		} else if (pid > 0)
			return EX_OK;

		if (setsid() < 0) {
			perror("setsid()");
			return EX_OSERR;
		}

		if (chdir("/") < 0) {
			perror("chdir(\"/\")");
			return EX_OSERR;
		}

		openlog(basename(argv[0]), LOG_PID, LOG_DAEMON);
	} else
		openlog(basename(argv[0]), LOG_PID | LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(debug));

	logger(LOG_NOTICE, 0, "started");

	mroute4 = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (mroute4 < 0)
		logger(LOG_WARNING, errno, "no IPv4 support");
	else {
		pim4 = pim_init(mroute4);
		if (pim4 < 0) {
			close(mroute4);
			mroute4 = -1;
		} else {
			add_poll(fds, &nfds, mroute4);
			add_poll(fds, &nfds, pim4);
		}
	}
	mroute6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (mroute6 < 0)
		logger(LOG_WARNING, errno, "no IPv6 support");
	else {
		pim6 = pim_init(mroute6);
		if (pim6 < 0) {
			close(mroute6);
			mroute6 = -1;
		} else {
			add_poll(fds, &nfds, mroute6);
			add_poll(fds, &nfds, pim6);
		}
	}

	if (mroute4 < 0 && mroute6 < 0) {
		logger(LOG_ERR, 0, "multicast routing unavailable");
		ret = -EX_OSERR;
		goto exit;
	}

	ret = route_init();
	if (ret)
		goto mroute;

	errno = 0;
	grgid = getgrnam(gid);
	if (grgid) {
		if (setgid(grgid->gr_gid))
			logger(LOG_WARNING, errno, "unable to drop group privileges");
	} else
		logger(LOG_WARNING, errno, "unable to find group '%s' to drop privileges to", gid);
	errno = 0;
	pwuid = getpwnam(uid);
	if (pwuid) {
		if (setuid(pwuid->pw_uid))
			logger(LOG_WARNING, errno, "unable to drop user privileges");
	} else
		logger(LOG_WARNING, errno, "unable to find user '%s' to drop privileges to", uid);

	ret = signals(&sig_handler);
	if (ret)
		goto route;

	ret = prime_timers(&timerid_mld, &timerid_pim);
	if (ret)
		goto signal;

	buf = malloc(SOCK_BUFLEN);
	if (buf == NULL) {
		logger(LOG_ERR, 0, "malloc()");
		ret = -EX_OSERR;
		goto timer;
	}

	while (running) {
		ret = poll(fds, nfds, -1);
		if (ret == -1) {
			if (errno == EINTR)
				continue;

			logger(LOG_ERR, errno, "poll()");
			ret = -EX_OSERR;
			running = 0;
			continue;
		}

		for (i = 0; i < nfds; i++) {
			/* TODO handle errors */
			assert(!(fds[i].revents & (POLLERR | POLLHUP)));

			/* either a non-event or there is something to read */
			assert(!fds[i].revents || fds[i].revents & POLLIN);

			if (!fds[i].revents)
				continue;

			if (fds[i].revents & POLLIN) {
				ret = _recvfrom(fds[i].fd, buf, SOCK_BUFLEN, 0,
						(struct sockaddr *)&src_addr,
						&addrlen);
				if (ret == -1) {
					logger(LOG_WARNING, errno, "recvfrom()");
					continue;
				}

				if (fds[i].fd == pim4 || fds[i].fd == pim6)
					pim_recv(fds[i].fd, buf, ret,
							&src_addr, addrlen);
				else
					mld_recv(fds[i].fd, buf, ret,
							&src_addr, addrlen);
			}
		}
	}

	free(buf);

timer:
	timer_delete(timerid_mld);
	timer_delete(timerid_pim);
signal:
	signals(SIG_IGN);
route:
	route_shutdown();
mroute:
	if (mroute4 > 0) {
		close(pim4);
		pim_shutdown(mroute4);
	}
	if (mroute6 > 0) {
		close(pim6);
		pim_shutdown(mroute6);
	}
exit:
	logger(LOG_NOTICE, 0, "exiting");

	closelog();

	assert(ret <= 0);

	return -ret;
}
