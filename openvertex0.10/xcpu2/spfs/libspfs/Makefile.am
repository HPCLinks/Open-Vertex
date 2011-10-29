#SYSNAME:=${shell uname}
#SYSNAME!=uname
#MULTILIBPATH=${shell test -d /lib64 && echo lib64 || echo lib}
HFILES=../include/spfs.h spfsimpl.h
AM_CFLAGS=-Wall -g -I ../include -D Linux

#Right now we dont support solaris

#ifeq ($(SYSNAME), SunOS)
#	CFLAGS += -D_POSIX_PTHREAD_SEMANTICS 
#endif
lib_LIBRARIES=libspfs.a
libspfs_a_SOURCES=conn.c error.c fcall.c fidpool.c file.c fmt.c np.c poll.c pvusers.c socksrv.c srv.c user.c uxusers.c

LIBFILES=\
	conn.o\
	error.o\
	fcall.o\
	fidpool.o\
	file.o\
	fmt.o\
	np.o\
	poll.o\
	pvusers.o\
	socksrv.o\
	srv.o\
	user.o\
	uxusers.o

libspfs.a: $(LIBFILES)
	ar rc libspfs.a $(LIBFILES)
	ranlib libspfs.a

install:
	mkdir -p $(prefix)/include
	mkdir -p $(prefix)/lib64
	cp ../include/spfs.h $(prefix)/include
	cp libspfs.a $(prefix)/lib64

clean:
	rm -f *.o *.a *~ core.*

$(LIBFILES): Makefile $(HFILES)

%.o: %.c 
	$(CC) $(AM_CFLAGS) -c $*.c
