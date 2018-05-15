/*
 * Soft:        socket_takeover is a proof-of-concept code to illustrate
 *		a seamless socket takeover technic between 2 processes.
 *		This design pattern can be used for mission critical daemon
 *		operating and handling sockets where down-time must be
 *		eradicated.
 *
 * Author:      Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2018 Alexandre Cassen, <acassen@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

/* local var */
static struct sockaddr_storage server_sockaddr;


/*
 *	Utilities functions
 */
static int
inet_stosockaddr(char *ip, const char *port, struct sockaddr_storage *addr)
{
	void *addr_ip;
	char *cp = ip;

	if (!ip || !port)
		return -1;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	/* remove range and mask stuff */
	if ((cp = strchr(ip, '-')))
		*cp = 0;
	else if ((cp = strchr(ip, '/')))
		*cp = 0;

	if (addr->ss_family == AF_INET6) { 
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		if (port)
			addr6->sin6_port = htons(atoi(port));
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		if (port)
			addr4->sin_port = htons(atoi(port));
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_pton(addr->ss_family, ip, addr_ip)) {
		addr->ss_family = AF_UNSPEC;
		return -1;
	}

	return 0;
}

static char *
inet_sockaddrtos2(struct sockaddr_storage *addr, char *addr_str)
{
	void *addr_ip;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_ntop(addr->ss_family, addr_ip, addr_str, INET6_ADDRSTRLEN))
		return NULL;

	return addr_str;
}

static char *
inet_sockaddrtos(struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN];
	inet_sockaddrtos2(addr, addr_str);
	return addr_str;
}

static uint16_t
inet_sockaddrport(struct sockaddr_storage *addr)
{
	uint16_t port;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		port = addr6->sin6_port;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		port = addr4->sin_port;
	}

	return port;
}


/*
 *	Socket related helpers
 */
int
if_setsockopt_reuseaddr(int fd, int onoff)
{
	int ret;

	if (fd < 0)
		return fd;

	/* reuseaddr option */
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &onoff, sizeof (onoff));
	if (ret < 0) {
		fprintf(stderr, "%s(): cant do SO_REUSEADDR errno=%d (%s)"
			      , __FUNCTION__, errno, strerror(errno));
		close(fd);
		fd = -1;
	}

	return fd;
}


/*
 *	Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -a, --connect-address	Connection Address\n");
	fprintf(stderr, "  -p, --connect-port		Connection Port\n");
	fprintf(stderr, "  -h, --help			Display this help message\n");
}


/*
 *	Command line parser
 */
static int
parse_cmdline(int argc, char **argv)
{
	int c, longindex, curind, ret;
	int bad_option = 0;
	char *server_addr = NULL, *server_port = NULL;

	struct option long_options[] = {
		{"connect-address",	required_argument,	NULL, 'a'},
		{"connect-port",	required_argument,	NULL, 'p'},
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":ha:p:"
						, long_options, &longindex)) != -1) {
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
                        break;
		case 'a':
			server_addr = optarg;
                        break;
		case 'p':
			server_port = optarg;
                        break;
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
			bad_option = 1;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = 1;
			break;
		default:
			exit(1);
			break;
		}
                curind = optind;
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (bad_option)
		exit(1);

	/* So far so good... */
	ret = inet_stosockaddr(server_addr, server_port, &server_sockaddr);
	if (ret < 0) {
		fprintf(stderr, "malformed IP Address or Port [%s]:%s !!!\n\n", server_addr, server_port);
		exit(1);
	}

	return 0;
}

/*
 *	TCP peers related
 */
static int
tcp_peer_read(int fd, char *data, int size)
{
	int nbytes, offset = 0;

next_rcv:
	nbytes = read(fd, data + offset, size - offset);

	/* data are ready ? */
	if (nbytes == -1 || nbytes == 0) {
		if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			goto next_rcv;
		return -1;
	}

	offset += nbytes;
	if (offset < size)
		goto next_rcv;

	return 0;
}

static int
tcp_peer_write(int fd, char *data, int size)
{
	int nbytes, offset = 0;

next_write:
	nbytes = send(fd, data + offset, size - offset, MSG_NOSIGNAL);

	/* data are ready ? */
	if (nbytes == -1 || nbytes == 0)
		return -1;

	offset += nbytes;
	if (offset < size)
		goto next_write;

	return nbytes;
}


/*
 *	TCP Client related
 */
static int
client_connect(struct sockaddr_storage *addr)
{
	socklen_t addrlen;
	int ret, fd;

	fd = socket(addr->ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return -1;

	fd = if_setsockopt_reuseaddr(fd, 1);
	if (fd < 0)
		return -1;

	/* Call connect function. */
	addrlen = sizeof(*addr);
	ret = connect(fd, (struct sockaddr *) addr, addrlen);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int
client_send(struct sockaddr_storage *addr)
{
	uint32_t seqnum = 0, *seq;
	char buffer[1024];
	int fd, ret;

	/* Connect remote server */
	fd = client_connect(addr);
	if (fd < 0) {
		fprintf(stderr, "%s(): Error connecting to remote server [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		return -1;
	}

	/* Send incremental seqnum */
	seq = (uint32_t *) buffer;
	for (seqnum = 0; ; seqnum++) {
		*seq = htonl(seqnum);
		ret = tcp_peer_write(fd, (char *) seq, sizeof(uint32_t));
		if (ret < 0)
			goto end;

		ret = tcp_peer_read(fd, buffer, sizeof(uint32_t));
		if (ret < 0)
			goto end;

		if (ntohl(*seq) != seqnum) {
			fprintf(stderr, "Seqnum discontinuity !!! (%d != %d)\n"
				      , ntohl(*seq)
				      , seqnum);
		}

		usleep(100000);
	}

  end:
	close(fd);
	return 0;
}


/*
 *	Main point
 */
int
main(int argc, char **argv)
{
	/* Init */
	memset(&server_sockaddr, 0, sizeof(struct sockaddr_storage));

	/* Command line parsing */
	parse_cmdline(argc, argv);

	/* Start client */
	client_send(&server_sockaddr);

	exit(0);
}
