SYSNAME:=${shell uname}
SYSNAME!=uname
INCDIR=../include
CFLAGS=-Wall -g -I $(INCDIR) -DSYSNAME=$(SYSNAME)
LFLAGS=-L. -L../libstrutil -lstrutil -L../libspclient -lspclient -L../libspfs -lspfs -lm -pthread
HFILES=$(INCDIR)/spfs.h $(INCDIR)/spclient.h $(INCDIR)/xcpu.h $(INCDIR)/strutil.h xtreefs.h

CMD=\
	xtreefs\

all: $(CMD)

clean:
	rm -f *.o *.a *~ core* $(CMD)


$(CMD): ../libspfs/libspfs.a ../libspclient/libspclient.a Makefile

xtreefs: xtreefs.o queue.o
	$(CC) $(CFLAGS) -o xtreefs xtreefs.o queue.o $(LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(CFLAGS) -c $*.c
