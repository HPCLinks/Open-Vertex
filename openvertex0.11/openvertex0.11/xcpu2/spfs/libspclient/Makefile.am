#SYSNAME:=${shell uname}
#SYSNAME!=uname
#MULTILIBPATH=${shell test -d /lib64 && echo lib64 || echo lib}
HFILES=../include/spfs.h ../include/spclient.h spcimpl.h
AM_CFLAGS=-Wall -g -I ../include
lib_LIBRARIES=libspclient.a
libspclient_a_SOURCES=dirread.c fid.c fsys.c mount.c netmount.c open.c pool.c poll.c read.c readnb.c remove.c stat.c stat2wstat.c walk.c write.c writenb.c wstat.c

LIBFILES=\
	dirread.o\
	fid.o\
	fsys.o\
	mount.o\
	netmount.o\
	open.o\
	pool.o\
	poll.o\
	read.o\
	readnb.o\
	remove.o\
	stat.o\
	stat2wstat.o\
	walk.o\
	write.o\
	writenb.o\
	wstat.o

libspclient.a: $(LIBFILES)
	ar rc libspclient.a $(LIBFILES)
	ranlib libspclient.a

#hack for x86_64
install:
	mkdir -p $(prefix)/include
	mkdir -p $(prefix)/lib64
	cp ../include/spclient.h $(prefix)/include
	cp libspclient.a $(prefix)/lib64

clean:
	rm -f *.o *.a *~
	make -C examples clean

$(LIBFILES): Makefile $(HFILES)

%.o: %.c 
	$(CC) $(AM_CFLAGS) -c $*.c
