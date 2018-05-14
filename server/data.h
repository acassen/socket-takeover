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

#ifndef _DATA_H
#define _DATA_H

/* Default values */
#define DEFAULT_PEER_NUMBER	(1 << 10)
#define DEFAULT_TCP_BACKLOG	10
#define DEFAULT_BUFFER_SIZE	1024

/* Peer info */
typedef struct _tcp_peer {
	pthread_t		task;
	pthread_attr_t		task_attr;
	struct sockaddr_storage	addr;
	int			fd;
	char			buffer[DEFAULT_BUFFER_SIZE];
	int			takeover;
	int			stop;

	list_head_t		next;
} tcp_peer_t;

/* dummy protocol header */
typedef struct _dummy_proto_hdr {
	uint32_t		seqnum;
} __attribute__((packed)) dummy_proto_hdr_t;

#endif
