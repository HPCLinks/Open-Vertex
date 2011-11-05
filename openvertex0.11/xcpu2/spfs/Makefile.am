#SYSNAME:=${shell uname}
#SYSNAME!=uname
AM_CFLAGS=-Wall -g 

SUBDIRS = libspfs libspclient fs


clean:
	rm -rf include/~


install :
	make -C libspfs install
	make -C libspclient install 
