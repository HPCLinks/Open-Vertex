SYSNAME:=${shell uname}
#SYSNAME!=uname
SUBDIRS= ../libstrutil ../libxauth ../libxcpu ../npfs ../spfs
INCDIR=../include
SPFSDIR=../spfs
AM_CFLAGS=-Wall -g -I $(INCDIR) -I $(SPFSDIR)/include -DSYSNAME=$(SYSNAME)
AM_LFLAGS=-g -L../libstrutil -lstrutil -L$(SPFSDIR)/libspclient -lspclient -L$(SPFSDIR)/libspfs -lspfs -L../libxauth -lxauth -lcrypto
HFILES=$(SPFSDIR)/include/spfs.h $(SPFSDIR)/include/spclient.h $(INCDIR)/strutil.h $(INCDIR)/libxauth.h xcpufs.h

FS=xcpufs xcpufs.static
OFILES=\
	pipe.o\
	proc-Linux.o\
	ufs.o\
	xauth.o\
	xcpufs.o

all: $(FS)

xcpufs: $(OFILES) $(HFILES) Makefile
	$(CC) -o xcpufs $(AM_CFLAGS) $(OFILES) $(AM_LFLAGS)

xcpufs.static: $(OFILES) $(HFILES) Makefile
	$(CC) -static -o xcpufs.static  $(AM_CFLAGS) $(OFILES) $(AM_LFLAGS) -ldl

install:
	mkdir -p $(prefix)/sbin
	for i in $(FS) ; do cp $$i $(prefix)/sbin ; done

clean:
	rm -f *.o *~ core* $(FS)

%.c: $(HFILES) Makefile

$(FS): $(SPFSDIR)/libspfs/libspfs.a $(SPFSDIR)/libspclient/libspclient.a ../libstrutil/libstrutil.a

%.o: %.c $(HFILES) Makefile
	$(CC) $(AM_CFLAGS) -c $*.c

