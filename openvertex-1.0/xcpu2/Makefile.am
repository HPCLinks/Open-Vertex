# This enables automatic library shipping. 

SYSNAME:=${shell uname}
#SYSNAME!=uname

SUBDIRS= libstrutil libxauth libxcpu  spfs npfs statfs xcpufs utils

INSTALLPREFIX:=@prefix@
export INSTALLPREFIX

LIBS=\
	libstrutil/libstrutil.a\
	libxauth/libxauth.a\
	libxcpu/libxcpu.a\
	spfs/libspclient/libspclient.a\
	spfs/libspfs/libspfs.a\
	npfs/libnpclient/libnpclient.a\
	npfs/libnpfs/libnpfs.a

all: binaries

clean:
	rm -f *~
	make -C libstrutil clean
	make -C libxauth clean
	make -C libxcpu clean
	make -C npfs clean
	make -C spfs clean
	make -C xcpufs clean
	make -C statfs clean
	make -C utils clean

computenodeinstall :
	make -C xcpufs install
install:
	make -C libstrutil install
	make -C libxauth install
	make -C libxcpu install
	make -C npfs install
	make -C spfs install
	make -C xcpufs install
	make -C statfs install
	make -C utils install

installman:
	mkdir -p $(INSTALLPREFIX)/share/man/man1
	mkdir -p $(INSTALLPREFIX)/share/man/man4
	cp man/man1/*.1 $(INSTALLPREFIX)/share/man/man1/
	cp man/man4/*.4 $(INSTALLPREFIX)/share/man/man4/

installscripts:
	make -C misc install

%.a:
	make -C libstrutil
	make -C libxauth
	make -C libxcpu
	make -C npfs/libnpclient
	make -C npfs/libnpfs
	make -C spfs/libspclient
	make -C spfs/libspfs

libs: $(LIBS)

binaries: libs
	make -C xcpufs
	make -C statfs
	make -C utils

xcpufs: libs
	make -C xcpufs

utils: libs
	make -C utils

statfs: libs
	make -C statfs
