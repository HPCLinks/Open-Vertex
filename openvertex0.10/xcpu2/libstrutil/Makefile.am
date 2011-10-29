

INCDIR=../include
HFILES=$(INCDIR)/strutil.h
AM_CFLAGS=-Wall -g -I$(INCDIR)



lib_LIBRARIES=libstrutil.a
libstrutil_a_SOURCES= quotestdrup.c unquotestr.c tokenize.c  custstr.c range.c
LIBFILES=\
        quotestrdup.o\
        unquotestr.o\
        tokenize.o\
        cutstr.o\
        range.o

libstrutil.a : $(LIBFILES)
	ar rc libstrutil.a $(LIBFILES)
	ranlib libstrutil.a



includedir=$(prefix)/include/
include_HEADERS = $(INCDIR)/strutil.h

#hack to get .a in lib64 for x86_64

archivedir=$(prefix)/lib64
archive_LIBRARIES=$(lib_LIBRARIES)

clean :	
	rm -rf *.o *.a *~ 


$(LIBFILES): Makefile $(HFILES)


%.o:%.c
	$(CC) $(AM_CFLAGS) -c $*.c
