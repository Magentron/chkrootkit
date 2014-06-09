#
# Makefile for chkrootkit
# (C) 1997-2007 Nelson Murilo, Pangeia Informatica, AMS Foundation and others.
#

CC       = cc
CFLAGS	 = -DHAVE_LASTLOG_H
STATIC   = -static

###
### Solaris 2.x
###
# If you have Solaris 2.x, uncomment the next two lines
#CFLAGS	 = -DHAVE_LASTLOG_H -DSOLARIS2
#LDFLAGS=-lsocket
# If you use gcc in Solaris don't uncomment STATIC line below
#STATIC = -B static

###
### Mac OS X
###
# If you have Mac OS X, uncomment the next line
#STATIC =

###
### FreeBSD or OpenBSD 2.x
###
# If you have FreeBSD or OpenBSD 2.x, uncomment the next line
#CFLAGS	 =


SRCS   = chklastlog.c chkwtmp.c ifpromisc.c chkproc.c chkdirs.c check_wtmpx.c strings.c

OBJS   = chklastlog.o chkwtmp.o ifpromisc.o chkproc.o chkdirs.o check_wtmpx.o strings-static.o

all:
	@echo '*** stopping make sense ***'
	@exec make sense

sense: chklastlog chkwtmp ifpromisc chkproc chkdirs check_wtmpx strings-static chkutmp

chklastlog:   chklastlog.c
	${CC} ${CFLAGS} -o $@ chklastlog.c
	@strip $@

chkwtmp:   chkwtmp.c
	${CC} ${CFLAGS} -o $@ chkwtmp.c
	@strip $@

ifpromisc:   ifpromisc.c
	${CC} ${CFLAGS} ${LDFLAGS}  -D_FILE_OFFSET_BITS=64 -o $@ ifpromisc.c
	@strip $@

chkproc:   chkproc.c
	${CC} ${LDFLAGS} -o $@ chkproc.c
	@strip $@

chkdirs:   chkdirs.c
	${CC} ${LDFLAGS} -o $@ chkdirs.c
	@strip $@

check_wtmpx:   check_wtmpx.c
	${CC} ${LDFLAGS} -o $@ check_wtmpx.c
	@strip $@

chkutmp:   chkutmp.c
	${CC} ${LDFLAGS} -o $@ chkutmp.c
	@strip $@


strings-static:   strings.c
	${CC} ${STATIC} ${LDFLAGS} -o $@ strings.c
	@strip $@

clean:
	rm -f ${OBJS} core chklastlog chkwtmp ifpromisc chkproc chkdirs check_wtmpx strings-static chkutmp
