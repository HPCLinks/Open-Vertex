
CMD=b256k b512k b1m b2m b4m b8m b16m

all: $(CMD)

b256k.o: b.c Makefile
	$(CC) -DSZ=256 -o $@ -c b.c

b512k.o: b.c Makefile
	$(CC) -DSZ=512 -o $@ -c b.c

b1m.o: b.c Makefile
	$(CC) -DSZ=1024 -o $@ -c b.c

b2m.o: b.c Makefile
	$(CC) -DSZ=2048 -o $@ -c b.c

b4m.o: b.c Makefile
	$(CC) -DSZ=4096 -o $@ -c b.c

b8m.o: b.c Makefile
	$(CC) -DSZ=8192 -o $@ -c b.c

b16m.o: b.c Makefile
	$(CC) -DSZ=16384 -o $@ -c b.c

clean:
	rm -f *.o *~ core* $(CMD)

%.c: $(HFILES) Makefile

$(FS): ../libspfs/libspfs.a ../libspclient/libspclient.a ../libstrutil/libstrutil.a

%.o: %.c $(HFILES) Makefile
	$(CC) $(CFLAGS) -c $*.c

