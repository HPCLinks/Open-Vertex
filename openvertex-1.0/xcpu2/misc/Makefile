SYSNAME:=${shell uname}
SYSNAME!=uname

INITSCRIPT=xcpufs xget

all: $(INITSCRIPT)

install:
	mkdir -p $(INSTALLPREFIX)/etc/init.d
	for i in $(INITSCRIPT) ; do cp $$i.sh $(INSTALLPREFIX)/etc/init.d/$$i ; done

clean:
	rm -f *.o *~ core*


