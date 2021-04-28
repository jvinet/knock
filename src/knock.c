/*
 *  knock.c
 *
 *  Copyright (c) 2004-2012 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <resolv.h>
#include <getopt.h>
#include <fcntl.h>

static char version[] = "0.8";

#define PROTO_TCP 1
#define PROTO_UDP 2

#define IP_DEFAULT AF_UNSPEC
#define IP_V4 AF_INET
#define IP_V6 AF_INET6

/* function prototypes */
void vprint(char *fmt, ...);
void ver();
void usage();

int o_verbose = 0;
int o_udp     = 0;
int o_delay   = 0;
int o_ip      = IP_DEFAULT;

int main(int argc, char** argv)
{
	int sd;
	int opt, optidx = 1;
	struct addrinfo hints;
	struct addrinfo *infoptr;
	char ipname[256];
	int result;
	char *hostname;
	static struct option opts[] =
	{
		{"verbose",   no_argument,       0, 'v'},
		{"udp",       no_argument,       0, 'u'},
		{"delay",     required_argument, 0, 'd'},
		{"help",      no_argument,       0, 'h'},
		{"version",   no_argument,       0, 'V'},
		{"ipv4",      no_argument,       0, '4'},
		{"ipv6",      no_argument,       0, '6'},
		{0, 0, 0, 0}
	};

	while((opt = getopt_long(argc, argv, "vud:hV46", opts, &optidx))) {
		if(opt < 0) {
			break;
		}
		switch(opt) {
			case 0:   break;
			case 'v': o_verbose = 1; break;
			case 'u': o_udp = 1; break;
			case 'd': o_delay = (int)atoi(optarg); break;
			case 'V': ver();
			case '4': o_ip = IP_V4; break;
			case '6': o_ip = IP_V6; break;
			case 'h': /* fallthrough */
			default: usage();
		}
	}
	if((argc - optind) < 2) {
		usage();
	}

	if(o_delay < 0) {
		fprintf(stderr, "error: delay cannot be negative\n");
		exit(1);
	}

	/* prepare hints to select ipv4 or v6 if asked */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = o_ip;
	hostname = argv[optind++];

	for(; optind < argc; optind++) {
		unsigned short proto = PROTO_TCP;
		const char *port;
		char *ptr, *arg = strdup(argv[optind]);

		if((ptr = strchr(arg, ':'))) {
			*ptr = '\0';
			port = arg;
			arg = ++ptr;
			if(!strcmp(arg, "udp")) {
				proto = PROTO_UDP;
			} else {
				proto = PROTO_TCP;
			}
		} else {
			port = arg;
		}

		/* get host and port based on hints */
		result = getaddrinfo(hostname, port, &hints, &infoptr);
		if(result) {
			fprintf(stderr, "Failed to resolve hostname '%s' on port %s\n", hostname, port);
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
			exit(1);
		}

		/* create socket */
		if(o_udp || proto == PROTO_UDP) {
			sd = socket(infoptr->ai_family, SOCK_DGRAM, 0);
			if(sd == -1) {
				fprintf(stderr, "Cannot open socket\n");
				exit(1);
			}
		} else {
			int flags;
			sd = socket(infoptr->ai_family, SOCK_STREAM, 0);
			if(sd == -1) {
				fprintf(stderr, "Cannot open socket\n");
				exit(1);
			}
			flags = fcntl(sd, F_GETFL, 0);
			fcntl(sd, F_SETFL, flags | O_NONBLOCK);
		}

		/* extract ip as string (v4 or v6) */
		getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen, ipname, sizeof(ipname), NULL, 0, NI_NUMERICHOST);

		/* connect or send UDP packet */
		if(o_udp || proto == PROTO_UDP) {
			vprint("hitting udp %s:%s\n", ipname, port);
			sendto(sd, "", 1, 0, infoptr->ai_addr, infoptr->ai_addrlen);
		} else {
			vprint("hitting tcp %s:%s\n", ipname, port);
			connect(sd, infoptr->ai_addr, infoptr->ai_addrlen);
		}

		close(sd);
		usleep(1000*o_delay);
		freeaddrinfo(infoptr);
	}

	return(0);
}

void vprint(char *fmt, ...)
{
	va_list args;
	if(o_verbose) {
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

void usage() {
	printf("usage: knock [options] <host> <port[:proto]> [port[:proto]] ...\n");
	printf("options:\n");
	printf("  -u, --udp            make all ports hits use UDP (default is TCP)\n");
	printf("  -d, --delay <t>      wait <t> milliseconds between port hits\n");
	printf("  -4, --ipv4           Force usage of IPv4\n");
	printf("  -6, --ipv6           Force usage of IPv6\n");
	printf("  -v, --verbose        be verbose\n");
	printf("  -V, --version        display version\n");
	printf("  -h, --help           this help\n");
	printf("\n");
	printf("example:  knock myserver.example.com 123:tcp 456:udp 789:tcp\n");
	printf("\n");
	exit(1);
}

void ver() {
	printf("knock %s\n", version);
	printf("Copyright (C) 2004-2012 Judd Vinet <jvinet@zeroflux.org>\n");
	exit(0);
}

/* vim: set ts=2 sw=2 noet: */
