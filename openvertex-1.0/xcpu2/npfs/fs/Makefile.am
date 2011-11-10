#SYSNAME:=${shell uname}
#SYSNAME!=uname

AM_CFLAGS=-Wall -g -I ../include -D Linux
AM_LFLAGS=-lpthread -L../libnpfs -lnpfs
GPHOTO_HPATH=/usr/include/gphoto2
GPHOTO_LPATH=/usr/lib
ETPAN_HPATH=/usr/include/libetpan
ETPAN_LPATH=/usr/lib
LIBDIRS:=/usr/lib/ /usr/local/lib/ /opt/lib/




#ifeq ($(SYSNAME),Linux)
NPFS_LFLAGS=-laio
#endif

FS=\
	npfs\
	ramfs\
	nullfs\
	ramfs2\
	echofs

#ifeq ($(SYSNAME),Linux)
	RDMADEPS:=\
		$(and $(foreach dir,$(LIBDIRS),$(wildcard $(dir)/libibverbs.*)), \
		$(foreach dir,$(LIBDIRS), $(wildcard $(dir)/librdmacm.*)))
	ifneq ($(strip $(RDMADEPS)),)
		FS += rdmanpfs
      # endif
#endif

.PHONY: all clean

all: $(FS)

npfs: ufs.o npfs.o
	$(CC) -o npfs $(AM_CFLAGS) ufs.o npfs.o $(AM_LFLAGS) $(NPFS_LFLAGS)

rdmanpfs: ufs.o rdmanpfs.o
	$(CC) -o rdmanpfs $(AM_CFLAGS) ufs.o rdmanpfs.o $(AM_LFLAGS) $(NPFS_LFLAGS) -libverbs -lrdmacm

ramfs: ramfs.o
	$(CC) -o ramfs $(AM_CFLAGS) ramfs.o $(AM_LFLAGS)

nullfs: nullfs.o
	$(CC) -o nullfs $(AM_CFLAGS) nullfs.o $(AM_LFLAGS)

ramfs2: ramfs2.o
	$(CC) -o ramfs2 $(AM_CFLAGS) ramfs2.o $(AM_LFLAGS)

gphotofs.o: gphotofs.c
	$(CC) $(AM_CFLAGS) -I $(GPHOTO_HPATH) -c $*.c

gphotofs: gphotofs.o
	$(CC) -o gphotofs $(AM_CFLAGS) gphotofs.o $(AM_LFLAGS) -L$(GPHOTO_LPATH) -lgphoto2

mboxfs.o: mboxfs.c
	$(CC) $(AM_CFLAGS) -I$(ETPAN_HPATH) -c $*.c

mboxfs: mboxfs.o
	$(CC) -o mboxfs $(AM_CFLAGS) mboxfs.o $(AM_LFLAGS) -L$(ETPAN_LPATH) -letpan -lssl -lcrypto -ldb-4.2 -lsasl2

echofs: echofs.o
	$(CC) -o echofs $(AM_CFLAGS) echofs.o $(AM_LFLAGS)

cpu: cpu.o ../libnpfs/libnpfs.a
	$(CC) -o cpu $(AM_CFLAGS) cpu.o $(AM_LFLAGS)

cpuhelper: cpuhelper.o
	$(CC) -o cpuhelper $(AM_CFLAGS) cpuhelper.o $(AM_LFLAGS)

clean:
	rm -f *.o $(FS) *~

%.c: ../include/npfs.h Makefile

$(FS): ../libnpfs/libnpfs.a

%.o: %.c 
	$(CC) $(AM_CFLAGS) -c $*.c

