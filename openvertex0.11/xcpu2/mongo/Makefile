SYSNAME:=${shell uname}
SYSNAME!=uname
INCDIR=../include
CFLAGS=-Wall -g -I $(INCDIR) -DSYSNAME=$(SYSNAME)
LFLAGS=-L. -L../libstrutil -lstrutil -L../libspfs -lspfs -L../libspclient -lspclient -lm -pthread
HFILES=$(INCDIR)/spfs.h $(INCDIR)/xcpu.h $(INCDIR)/strutil.h mongo.h

CMD=\
	mongo\

all: $(CMD)

clean:
	rm -f *.o *.a *~ core* $(CMD)

install:
	mkdir -p $(INSTALLPREFIX)/sbin
	for i in $(CMD) ; do cp $$i $(INSTALLPREFIX)/sbin ; done


$(CMD): ../libspfs/libspfs.a Makefile

mongo: mongo.o 
	$(CC) $(CFLAGS) -o mongo mongo.o $(LFLAGS)

%.o: %.c $(HFILES)
	$(CC) $(CFLAGS) -c $*.c
