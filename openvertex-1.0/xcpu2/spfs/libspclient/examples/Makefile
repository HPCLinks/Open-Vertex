SYSNAME:=${shell uname}
SYSNAME!=uname
CFLAGS=-Wall -g -I ../../include
LFLAGS=-L../../libspfs -L.. -lspclient -lspfs

CMD=\
	9ls\
	9write\
	9read\
	9read2\
	9readnb\

all: $(CMD)

9ls: 9ls.o ../../libspfs/libspfs.a ../libspclient.a 
	$(CC) -o 9ls $(CFLAGS) 9ls.o $(LFLAGS)

9write: 9write.o ../../libspfs/libspfs.a ../libspclient.a
	$(CC) -o 9write $(CFLAGS) 9write.o $(LFLAGS)

9read: 9read.o ../../libspfs/libspfs.a ../libspclient.a
	$(CC) -o 9read $(CFLAGS) 9read.o $(LFLAGS)

9read2: 9read2.o ../../libspfs/libspfs.a ../libspclient.a
	$(CC) -o 9read2 $(CFLAGS) 9read2.o $(LFLAGS)

9readnb: 9readnb.o ../../libspfs/libspfs.a ../libspclient.a
	$(CC) -o 9readnb $(CFLAGS) 9readnb.o $(LFLAGS)

clean:
	rm -f *.o *.a *~ $(CMD)

%.o: %.c 
	$(CC) $(CFLAGS) -c $*.c
