Socket Takeover: Socket takeover from one process to another
============================================================

When you are running business mission critical services you MUST rely on
design offering zero downtime. It is truly the case when considering
upgrading/updating such mission critical software components.

This software introduce a design pattern to perform seamless TCP socket
takeover from one process to another. The code here is just a proof of
concept and can be used for experimentation or integration into more
complex software component.

This source code is using design present in 4.4BSD systems. Using SCM_RIGHTS
ancillary data over a Unix domain socket to transport a set of file descriptors.
You can find more informations on this technic by reading good litterature from
[W. Richard Stevens: UNIX Network Programming Volume 1 Third Edition], section 15.7.
The code proposed here will make it more Linux specific by introducting a mechanism
to takeover and synchronize client/server interactions.


# Content

2 directory are available :

	* server : TCP server code
	* client : TCP client code


# Give it a try : Server side

$ cd server
$ make
$ ./server -h
Usage: ./server [OPTION...]
  -a, --listen-address		Address to bind TCP listener on
  -p, --listen-port		Port to bind TCP listener on
  -b, --listen-backlog		TCP listener backlog
  -t, --takeover-path		Takeover channel unix domain path
  -T, --takeover		Perform takeover operation
  -h, --help			Display this help message
$ ./server -a 127.0.0.1 -p 1234 -t /tmp/.takeover


# Give it a try : Client side

$ cd client
$ make
$ ./client -h
Usage: ./client [OPTION...]
  -a, --listen-address		Log messages to local console
  -p, --listen-port		Detailed log messages
  -h, --help			Display this help message
$ ./client -a 127.0.0.1 -p 1234


# Having fun

	[client]$ ./client -a 127.0.0.1 -p 1234


	[server/sh1]$ ./server -a 127.0.0.1 -p 1234 -t /tmp/.takeover
	Starting TCP server on [127.0.0.1]:1234 (fd:3)
	Starting Takeover channel on [/tmp/.takeover] domain socket
	Accepting connection from Peer [127.0.0.1]:57796 (fd:4)
	Starting connection with Peer [127.0.0.1]:57796 (fd:4)
	[127.0.0.1]:57796 - seqnum:0
	[127.0.0.1]:57796 - seqnum:1
	[127.0.0.1]:57796 - seqnum:2
	[127.0.0.1]:57796 - seqnum:3
	[127.0.0.1]:57796 - seqnum:4
	[127.0.0.1]:57796 - seqnum:5
	[127.0.0.1]:57796 - seqnum:6
	[127.0.0.1]:57796 - seqnum:7
	[127.0.0.1]:57796 - seqnum:8
	[127.0.0.1]:57796 - seqnum:9
	[127.0.0.1]:57796 - seqnum:10
	[127.0.0.1]:57796 - seqnum:11
	[127.0.0.1]:57796 - seqnum:12
	[127.0.0.1]:57796 - seqnum:13
	[127.0.0.1]:57796 - seqnum:14
	[127.0.0.1]:57796 - seqnum:15
	[127.0.0.1]:57796 - seqnum:16
	[127.0.0.1]:57796 - seqnum:17
	[127.0.0.1]:57796 - seqnum:18
	[127.0.0.1]:57796 - seqnum:19
	Accepting connection from Takeover channel
	Current fd_array:={[3][4]}
	[127.0.0.1]:57796 - seqnum:20
	Holding connection with Peer [127.0.0.1]:57796 (fd:4)
	Releasing Peer [127.0.0.1]:57796 (fd:4)
	tcp_peer_release(): Tcp peers released...


	[server/sh2]$ ./server -T /tmp/.takeover 
	Starting connection with Peer [127.0.0.1]:57796 (fd:5)
	Starting Takeover channel on [/tmp/.takeover] domain socket
	[127.0.0.1]:57796 - seqnum:21
	[127.0.0.1]:57796 - seqnum:22
	[127.0.0.1]:57796 - seqnum:23
	[127.0.0.1]:57796 - seqnum:24
	[127.0.0.1]:57796 - seqnum:25
	[127.0.0.1]:57796 - seqnum:26
	[127.0.0.1]:57796 - seqnum:27
	[127.0.0.1]:57796 - seqnum:28
	[127.0.0.1]:57796 - seqnum:29
	...


Enjoy,
Alexandre

