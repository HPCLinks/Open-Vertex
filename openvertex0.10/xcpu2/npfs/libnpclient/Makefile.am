#SYSNAME:=${shell uname}
#SYSNAME!=uname
#MULTILIBPATH=${shell test -d /lib64 && echo lib64 || echo lib}
HFILES=../include/npfs.h ../include/npclient.h npcimpl.h
AM_CFLAGS=-Wall -g -I ../include
lib_LIBRARIES=libnpclient.a
libnpclient_a_SOURCES= dirread.c fid.c fsysy.c mount.c netmount.c open.c pool.c read.c remove.c stat.c stat2wstat.c walk.c write.c

LIBFILES=\
	dirread.o\
	fid.o\
	fsys.o\
	mount.o\
	netmount.o\
	open.o\
	pool.o\
	read.o\
	remove.o\
	stat.o\
	stat2wstat.o\
	walk.o\
	write.o

libnpclient.a: $(LIBFILES)
	ar rc libnpclient.a $(LIBFILES)
	ranlib libnpclient.a

install:
	mkdir -p $(prefix)/include
	mkdir -p $(prefix)/lib64
	cp ../include/npclient.h $(prefix)/include
	cp libnpclient.a $(prefix)/lib64

clean:
	rm -f *.o *.a *~
	make -C examples clean

$(LIBFILES): Makefile $(HFILES)

%.o: %.c 
	$(CC) $(AM_CFLAGS) -c $*.c
