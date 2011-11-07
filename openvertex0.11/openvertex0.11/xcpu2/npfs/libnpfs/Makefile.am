SYSNAME:=${shell uname}
#SYSNAME!=uname
#MULTILIBPATH=${shell test -d /lib64 && echo lib64 || echo lib}
HFILES=../include/npfs.h npfsimpl.h
AM_CFLAGS=-Wall -g -I../include -D Linux
INCLUDEDIRS:=/usr/include/ /usr/local/include/ /opt/include/

#No solaris support right now

##ifeq ($(SYSNAME), SunOS)
#	CFLAGS += -D_POSIX_PTHREAD_SEMANTICS
#endif

.PHONY: all clean

.all: libnpfs.a

lib_LIBRARIES=libnpfs.a
libnpfs_a_SOURCES = conn.c error.c fcall.c fdtrans.c fidpool.c file.c fmt.c np.c pvusers.c socksrv.c srv.c trans.c user.c uxusers.c

LIBFILES=\
	conn.o\
	error.o\
	fcall.o\
	fdtrans.o\
	fidpool.o\
	file.o\
	fmt.o\
	np.o\
	pvusers.o\
	socksrv.o\
	srv.o\
	trans.o\
	user.o\
	uxusers.o\
	pipesrv.o

#ifeq ($(SYSNAME), Linux)
	LIBFILES += pipesrv.o
	RDMADEPS:=\
		$(and $(foreach dir,$(INCLUDEDIRS),$(wildcard $(dir)/rdma/rdma_cma.h)), \
		$(foreach dir,$(INCLUDEDIRS), $(wildcard $(dir)/infiniband/verbs.h)))
	ifneq ($(strip $(RDMADEPS)),)
		LIBFILES += rdmasrv.o rdmatrans.o
	endif
#endif

libnpfs.a: $(LIBFILES)
	ar rc libnpfs.a $(LIBFILES)
	ranlib libnpfs.a

install:
	mkdir -p $(prefix)/include
	mkdir -p $(prefix)/lib64
	cp ../include/npfs.h $(prefix)/include
	cp libnpfs.a $(prefix)/lib64


clean:
	rm -f *.o *.a *~ core.*

$(LIBFILES): Makefile $(HFILES)

%.o: %.c 
	$(CC) $(AM_CFLAGS) -c $*.c

