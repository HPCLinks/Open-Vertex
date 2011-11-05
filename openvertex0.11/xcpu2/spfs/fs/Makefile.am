#SYSNAME:=${shell uname}
#SYSNAME!=uname
AM_CFLAGS=-Wall -g -I ../include -DSYSNAME=Linux
AM_LFLAGS=-L../libspfs -lspfs

FS=\
	ufs

all: ufs

ufs: ufs.o
	$(CC) -o ufs $(CFLAGS) ufs.o $(AM_LFLAGS) $(NPFS_LFLAGS)

clean:
	rm -f *.o *~ $(FS) core.*

%.c: ../include/spfs.h Makefile

$(FS): ../libspfs/libspfs.a

%.o: %.c 
	$(CC) $(AM_CFLAGS) -c $*.c

