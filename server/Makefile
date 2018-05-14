#
# Soft:        socket_takeover is a proof-of-concept code to illustrate
#              a seamless socket takeover technic between 2 processes.
#              This design pattern can be used for mission critical daemon
#              operating and handling sockets where down-time must be
#              eradicated.
#
# Author:      Alexandre Cassen, <acassen@gmail.com>
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#              See the GNU General Public License for more details.
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU General Public License
#              as published by the Free Software Foundation; either version
#              2 of the License, or (at your option) any later version.
#
# Copyright (C) 2018 Alexandre Cassen, <acassen@gmail.com>
#

EXEC= server
CC= gcc
CFLAGS= -Wall -Wstrict-prototypes -Wpointer-arith -O3 -fomit-frame-pointer -fexpensive-optimizations
LDLIBS= -lpthread
OBJECTS= main.o
.c.o:	
	$(CC) -o $@ $(CFLAGS) -c $*.c

all:	$(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC):	$(OBJECTS)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS) $(LDLIBS) -ggdb

clean:
	-rm -f *.o $(EXEC) 

