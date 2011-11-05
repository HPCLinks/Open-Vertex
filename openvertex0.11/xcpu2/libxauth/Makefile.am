INCDIR=../include
SPFSDIR=../spfs
HFILES=$(SPFSDIR)/include/spfs.h $(INCDIR)/libxauth.h
AM_FLAGS=-Wall -g -I$(INCDIR) -I$(SPFSDIR)/include
lib_LIBRARIES=libxauth.a
libxauth_a_SOURCES=xauth.c

LIBFILES=\
	xauth.o

libxauth.a: $(LIBFILES)
	ar rc libxauth.a $(LIBFILES)
	ranlib libxauth.a

includedir=$(prefix)/include/
include_HEADERS = $(INCDIR)/libxauth.h

#hack to get .a in lib64 for x86_64

archivedir=$(prefix)/lib64
archive_LIBRARIES=$(lib_LIBRARIES)


clean:
	rm -f *.o *.a *~

xtest: xtest.c libxauth.a
	$(CC) -o xtest $(AM_CFLAGS) xtest.c -L$(SPFSDIR)/libspfs -lspfs -L. -lxauth -lcrypto

$(LIBFILES): Makefile $(HFILES)

%.o: %.c 
	$(CC) -Wall -I$(INCDIR) -I$(SPFSDIR) -c $*.c
