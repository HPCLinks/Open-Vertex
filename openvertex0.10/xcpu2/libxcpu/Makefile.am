INCDIR=../include
SPFSDIR=../spfs
HFILES=../include/libxcpu.h xcpuimpl.h ../include/xcpu.h $(SPFSDIR)/include/spfs.h $(SPFSDIR)/include/spclient.h
AM_FLAGS=-Wall -g -I ../include -I$(SPFSDIR)/include 
lib_LIBRARIES=libxcpu.a
libxcpu_a_SOURCES=command.c  file.c node.c proc.c session.c ufs.c user.c group.c util.c

LIBFILES=\
	command.o\
	file.o\
	node.o\
	proc.o\
	session.o\
	ufs.o\
	user.o\
	group.o\
	util.o

libxcpu.a: $(LIBFILES)
	ar rc libxcpu.a $(LIBFILES)
	ranlib libxcpu.a


includedir=$(prefix)/include/
include_HEADERS = $(INCDIR)/libxcpu.h  $(INCDIR)/xcpu.h

#hack to get .a in lib64 for x86_64

archivedir=$(prefix)/lib64
archive_LIBRARIES=$(lib_LIBRARIES)


clean:
	rm -f *.o *.a *~ core.*

$(LIBFILES): Makefile $(HFILES)

%.o: %.c
	$(CC) -Wall -I$(INCDIR) -I$(SPFSDIR) -c $*.c

