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
#include <sys/socket.h>
#include <sys/un.h>
#include "list_head.h"
#include "data.h"

/* local var */
static struct sockaddr_storage listen_sockaddr;
static int listen_fd;
static int listen_backlog = DEFAULT_TCP_BACKLOG;
static list_head_t tcp_peers;
static int tcp_peers_cnt = 0;
static pthread_mutex_t tcp_peers_mutex = PTHREAD_MUTEX_INITIALIZER;
static int takeover = 0;
static char *takeover_path = NULL;
static pthread_t takeover_task;


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
inet_sockaddrtos(struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN];
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
	fprintf(stderr, "  -a, --listen-address		Address to bind TCP listener on\n");
	fprintf(stderr, "  -p, --listen-port		Port to bind TCP listener on\n");
	fprintf(stderr, "  -b, --listen-backlog		TCP listener backlog\n");
	fprintf(stderr, "  -t, --takeover-path		Takeover channel unix domain path\n");
	fprintf(stderr, "  -T, --takeover		Perform takeover operation\n");
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
	char *listen_addr = NULL, *listen_port = NULL;

	struct option long_options[] = {
		{"listen-address",	optional_argument,	NULL, 'a'},
		{"listen-port",		optional_argument,	NULL, 'p'},
		{"listen-backlog",	optional_argument,	NULL, 'b'},
		{"takeover-path",	optional_argument,	NULL, 't'},
		{"takeover",		optional_argument,	NULL, 'T'},
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":ha:p:b:t:T:"
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
			listen_addr = optarg;
                        break;
		case 'p':
			listen_port = optarg;
                        break;
		case 'b':
			listen_backlog = atoi(optarg);
			break;
		case 't':
			takeover_path = optarg;
			break;
		case 'T':
			takeover_path = optarg;
			takeover = 1;
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
	if (!listen_addr && !listen_port)
		return 0;

	ret = inet_stosockaddr(listen_addr, listen_port, &listen_sockaddr);
	if (ret < 0) {
		fprintf(stderr, "malformed IP Address or Port [%s]:%s !!!\n\n", listen_addr, listen_port);
		exit(1);
	}

	return 0;
}

/*
 *	TCP peers related
 */
static int
tcp_peer_add(tcp_peer_t *tcp_peer)
{
	pthread_mutex_lock(&tcp_peers_mutex);
	list_add_tail(&tcp_peer->next, &tcp_peers);
	tcp_peers_cnt++;
	pthread_mutex_unlock(&tcp_peers_mutex);
	return 0;
}

static int
tcp_peer_del(tcp_peer_t *tcp_peer)
{
	pthread_mutex_lock(&tcp_peers_mutex);
	list_head_del(&tcp_peer->next);
	tcp_peers_cnt--;
	pthread_mutex_unlock(&tcp_peers_mutex);
	return 0;
}

static int
tcp_peer_release(void)
{
	tcp_peer_t *tcp_peer, *tmp;

  retry:
	pthread_mutex_lock(&tcp_peers_mutex);
	list_for_each_entry_safe(tcp_peer, tmp, &tcp_peers, next) {
		if (tcp_peer->takeover == 2) {
			printf("Releasing Peer [%s]:%d (fd:%d)\n"
			       , inet_sockaddrtos(&tcp_peer->addr)
			       , ntohs(inet_sockaddrport(&tcp_peer->addr))
			       , tcp_peer->fd);
			close(tcp_peer->fd);
			list_head_del(&tcp_peer->next);
			tcp_peers_cnt--;
			free(tcp_peer);
		}
	}
	pthread_mutex_unlock(&tcp_peers_mutex);

	if (tcp_peers_cnt > 0) {
		usleep(100000);
		goto retry;
	}

	fprintf(stderr, "%s(): Tcp peers released...\n", __FUNCTION__);

	return 0;
}

static int
tcp_peer_fd_cpy(int *fds, int fdsize)
{
	tcp_peer_t *tcp_peer;
	int i = 0;

	pthread_mutex_lock(&tcp_peers_mutex);
	list_for_each_entry(tcp_peer, &tcp_peers, next) {
		tcp_peer->takeover = 1;
		fds[i++] = tcp_peer->fd;
		if (i > fdsize)
			break;
	}
	pthread_mutex_unlock(&tcp_peers_mutex);
	return 0;
}

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

static void *
tcp_peer_task(void *arg)
{
	tcp_peer_t *tcp_peer = arg;
	dummy_proto_hdr_t *hdr;
	int ret;

        printf("Starting connection with Peer [%s]:%d (fd:%d)\n"
	       , inet_sockaddrtos(&tcp_peer->addr)
	       , ntohs(inet_sockaddrport(&tcp_peer->addr))
	       , tcp_peer->fd);

	for (;;) {
		if (tcp_peer->stop)
			goto end;

		if (tcp_peer->takeover) {
			tcp_peer->takeover = 2;
			printf("Holding connection with Peer [%s]:%d (fd:%d)\n"
			       , inet_sockaddrtos(&tcp_peer->addr)
			       , ntohs(inet_sockaddrport(&tcp_peer->addr))
			       , tcp_peer->fd);
			return NULL;
		}

		ret = tcp_peer_read(tcp_peer->fd, tcp_peer->buffer, sizeof(dummy_proto_hdr_t));
		if (ret < 0)
			goto end;

		hdr = (dummy_proto_hdr_t *) tcp_peer->buffer;
		printf("[%s]:%d - seqnum:%d\n"
		       , inet_sockaddrtos(&tcp_peer->addr)
		       , ntohs(inet_sockaddrport(&tcp_peer->addr))
		       , ntohl(hdr->seqnum));

		ret = tcp_peer_write(tcp_peer->fd, tcp_peer->buffer, sizeof(dummy_proto_hdr_t));
		if (ret < 0)
			goto end;
	}

  end:
	printf("Stopping connection with Peer [%s]:%d (fd:%d)\n"
	       , inet_sockaddrtos(&tcp_peer->addr)
	       , ntohs(inet_sockaddrport(&tcp_peer->addr))
	       , tcp_peer->fd);
	close(tcp_peer->fd);
	tcp_peer_del(tcp_peer);
	free(tcp_peer);
	return NULL;
}

static int
tcp_peer_start(int fd, struct sockaddr_storage *addr)
{
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	tcp_peer_t *tcp_peer;
	int ret;

	/* Create new TCP Peer control block */
	tcp_peer = (tcp_peer_t *) malloc(sizeof(tcp_peer_t));
	memset(tcp_peer, 0, sizeof(tcp_peer_t));
	INIT_LIST_HEAD(&tcp_peer->next);
	tcp_peer->fd = fd;
	tcp_peer_add(tcp_peer);

	/* Retreive peer info */
	if (addr) {
		tcp_peer->addr = *addr;
	} else {
		ret = getpeername(fd, (struct sockaddr *) &tcp_peer->addr, &addrlen);
		if (ret < 0) {
			fprintf(stderr, "%s(): cant retrieve peer address from socket:%d (%m)\n"
				      , __FUNCTION__
				      , fd);
		}
	}

	/* Spawn a dedicated pthread handler */
	ret = pthread_attr_init(&tcp_peer->task_attr);
	if (ret != 0) {
		fprintf(stderr, "%s(): cant initialize pthread attr for tcp_peer [%s]:%d (%m)\n"
			      , __FUNCTION__
			      , inet_sockaddrtos(&tcp_peer->addr)
			      , ntohs(inet_sockaddrport(&tcp_peer->addr)));
		tcp_peer_del(tcp_peer);
		close(tcp_peer->fd);
		free(tcp_peer);
		return -1;
	}

	ret = pthread_attr_setdetachstate(&tcp_peer->task_attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		fprintf(stderr, "%s(): cant set detach attr to pthread for tcp_peer [%s]:%d (%m)\n"
			      , __FUNCTION__
			      , inet_sockaddrtos(&tcp_peer->addr)
			      , ntohs(inet_sockaddrport(&tcp_peer->addr)));
		tcp_peer_del(tcp_peer);
		close(tcp_peer->fd);
		free(tcp_peer);
		return -1;
	}

	ret = pthread_create(&tcp_peer->task, &tcp_peer->task_attr, tcp_peer_task, tcp_peer);
	if (ret != 0) {
		fprintf(stderr, "%s(): cant create pthread for tcp_peer [%s]:%d (%m)\n"
			      , __FUNCTION__
			      , inet_sockaddrtos(&tcp_peer->addr)
			      , ntohs(inet_sockaddrport(&tcp_peer->addr)));
		tcp_peer_del(tcp_peer);
		close(tcp_peer->fd);
		free(tcp_peer);
		return -1;
	}

	return 0;
}


/*
 *	TCP listener related
 */
static int
server_accept(int fd)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	int accept_fd;

  next_accept:
	accept_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
	if (accept_fd < 0) {
		fprintf(stderr, "%s(): Error accepting connection from peer [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(&addr)
			      , ntohs(inet_sockaddrport(&addr)));
		return -1;
	}

	/* Register read thread on accept fd */
        printf("Accepting connection from Peer [%s]:%d (fd:%d)\n"
	       , inet_sockaddrtos(&addr)
	       , ntohs(inet_sockaddrport(&addr))
	       , accept_fd);

	tcp_peer_start(accept_fd, &addr);

	goto next_accept;

	return 0;
}


static int
server_listen(struct sockaddr_storage *addr)
{
	mode_t old_mask;
	int err;
	socklen_t addrlen;

	/* Mask */
	old_mask = umask(0077);

	/* Create main listening socket */
	listen_fd = socket(addr->ss_family, SOCK_STREAM, 0);
	listen_fd = if_setsockopt_reuseaddr(listen_fd, 1);
	if (listen_fd < 0) {
		fprintf(stderr, "%s() error creating [%s]:%d socket"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		return -1;
	}

	/* Bind listening channel */
	addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	err = bind(listen_fd, (struct sockaddr *) addr, addrlen);
	if (err < 0) {
		fprintf(stderr, "%s(): Error binding to [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		goto error;
	}

	/* Init listening channel */
	err = listen(listen_fd, listen_backlog);
	if (err < 0) {
		fprintf(stderr, "%s(): Error listening on [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		goto error;
	}

	/* Restore old mask */
	umask(old_mask);

	/* Welcome banner */
	printf("Starting TCP server on [%s]:%d (fd:%d)\n"
	       , inet_sockaddrtos(&listen_sockaddr)
	       , ntohs(inet_sockaddrport(&listen_sockaddr))
	       , listen_fd);

	server_accept(listen_fd);
	close(listen_fd);
	return 0;

  error:
	close(listen_fd);
	return -1;
}


/*
 *	UNIX domain related
 */
static int
takeover_connect(char *path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int err, fd;

	/* Create UNIX domain socket */
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "%s() error creating [%s] domain socket"
			      , __FUNCTION__
			      , path);
		return -1;
	}

	/* Target channel */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, strlen(path));
	addrlen = sizeof(addr.sun_family) + strlen(path);
	err = connect(fd, (struct sockaddr *) &addr, addrlen);
	if (err < 0) {
		fprintf(stderr, "%s(): Error connecting to [%s] domain socket (%m)"
			      , __FUNCTION__
			      , path);
		close(fd);
		return -1;
	}

	return fd;
}

static int
takeover_fetch(void)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char ctrl[1024];
	int fd_cnt;
	int fd, lfd = -1, ret, *fds, i;

	fd = takeover_connect(takeover_path);
	if (fd < 0)
		return -1;

	memset(ctrl, 0, 1024);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof(ctrl);
	iov.iov_base = (char *) &fd_cnt;
	iov.iov_len = sizeof(int);

	ret = recvmsg(fd, &msg, 0);
	if (ret <= 0) {
		fprintf(stderr, "%s(): Error recvmsg(%m) over domain socket\n"
			      , __FUNCTION__);
		goto end;
	}

	/* Process Ancillary data */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
		goto end;

	fds = (int *) CMSG_DATA(cmsg);

	/* Restore Listen fd */
	lfd = *fds;

	/* Restore peer related */
	for (i=1; i < fd_cnt; i++) {
		tcp_peer_start(*(fds+i), NULL);
	}

  end:
	close(fd);
	return lfd;
}

static int
takeover_send(int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	int fd_cnt = tcp_peers_cnt + 1;
	int *fds, ret, i;
	union {
		char ctrl[CMSG_SPACE(sizeof(int) * fd_cnt)];
		struct cmsghdr align;
	} u;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = u.ctrl;
	msg.msg_controllen = sizeof u.ctrl;

	iov.iov_base = (char *) &fd_cnt;
	iov.iov_len = sizeof(int);

	/* Ancillary_data */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fd_cnt);

	/* fill in payload */
	fds = (int *) CMSG_DATA(cmsg);
	*fds = listen_fd; /* First array element is global listen fd */
	tcp_peer_fd_cpy(fds+1, sizeof(int) * tcp_peers_cnt);

	printf("Current fd_array:={");
	for (i=0; i < fd_cnt; i++) {
		printf("[%d]", fds[i]);
	}
	printf("}\n");

	ret = sendmsg(fd, &msg, MSG_NOSIGNAL);
	if (ret < 0) {
		fprintf(stderr, "%s(): Error sendmsg(%m) over domain socket\n"
			      , __FUNCTION__);
	}

	/* Release pending peers */
	tcp_peer_release();
	close(listen_fd);
	return 0;
}

static int
takeover_accept(int fd)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	int accept_fd;

  next_accept:
	accept_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
	if (accept_fd < 0) {
		fprintf(stderr, "%s(): Error accepting connection from domain socket (%m)"
			      , __FUNCTION__);
		goto next_accept;
	}

	/* Register read thread on accept fd */
        printf("Accepting connection from Takeover channel\n");

	/* sending socket array */
	close(fd);
	takeover_send(accept_fd);
	close(accept_fd);
	return 0;
}

static int
takeover_listen(char *path)
{
	struct sockaddr_un addr;
	mode_t old_mask;
	int err, fd;
	socklen_t addrlen;

	/* Mask */
	old_mask = umask(0077);

	/* Create UNIX domain socket */
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "%s() error creating [%s] domain socket"
			      , __FUNCTION__
			      , path);
		return -1;
	}

	/* Bind listening channel */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, strlen(path));
	addrlen = sizeof(addr.sun_family) + strlen(path);
	err = bind(fd, (struct sockaddr *) &addr, addrlen);
	if (err < 0) {
		fprintf(stderr, "%s(): Error binding to [%s] domain socket (%m)"
			      , __FUNCTION__
			      , path);
		goto error;
	}

	/* Init listening channel */
	err = listen(fd, 1);
	if (err < 0) {
		fprintf(stderr, "%s(): Error listening on [%s] domain socket (%m)"
			      , __FUNCTION__
			      , path);
		goto error;
	}

	/* Restore old mask */
	umask(old_mask);

	/* Welcome banner */
	printf("Starting Takeover channel on [%s] domain socket\n"
	       , path);

	takeover_accept(fd);
	return 0;

  error:
	close(fd);
	return -1;
}

static void *
takeover_channel_task(void *arg)
{
	unlink(takeover_path);
	takeover_listen(takeover_path);
	return NULL;
}


/*
 *	Main point
 */
int
main(int argc, char **argv)
{
	/* Init */
	memset(&listen_sockaddr, 0, sizeof(struct sockaddr_storage));
	INIT_LIST_HEAD(&tcp_peers);

	/* Command line parsing */
	parse_cmdline(argc, argv);

	if (takeover) {
		/* Restore listener and peers from remote */
		listen_fd = takeover_fetch();
		if (listen_fd < 0) {
			fprintf(stderr, "Error while taking over remote daemon socket!\n");
			exit(-1);
		}

		/* Start takeover channel */
		pthread_create(&takeover_task, NULL, takeover_channel_task, NULL);

		/* Start main TCP listener */
		server_accept(listen_fd);
	} else {
		/* Start takeover channel */
		pthread_create(&takeover_task, NULL, takeover_channel_task, NULL);

		/* Start listener */
		server_listen(&listen_sockaddr);
	}

	exit(0);
}
