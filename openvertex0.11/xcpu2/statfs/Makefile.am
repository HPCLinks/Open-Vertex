SYSNAME:=${shell uname}
#SYSNAME!=uname
INCDIR=../include
NPFSDIR=../npfs
AM_CFLAGS=-Wall -g -I $(INCDIR) -I$(NPFSDIR)/include -DSYSNAME=$(SYSNAME)
AM_LFLAGS=-L. -L../libstrutil -lstrutil -L$(NPFSDIR)/libnpclient -lnpclient -L$(NPFSDIR)/libnpfs -lnpfs -lcrypto -lm -lpthread
HFILES=$(NPFSDIR)/include/npfs.h $(NPFSDIR)/include/npclient.h $(INCDIR)/xcpu.h $(INCDIR)/strutil.h

CMD=\
	statfs

all: $(CMD)

clean:
	rm -f *.o *.a *~ core* $(CMD)

install:
	mkdir -p $(prefix)/bin
	for i in $(CMD) ; do cp $$i $(prefix)/bin ; done

$(CMD): $(NPFSDIR)/libnpclient/libnpclient.a ../libstrutil/libstrutil.a $(NPFSDIR)/libnpfs/libnpfs.a Makefile

statfs: statfs.o xauth.o
	$(CC) $(AM_CFLAGS) -o statfs xauth.o statfs.o $(AM_LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(AM_CFLAGS) -c $*.c

