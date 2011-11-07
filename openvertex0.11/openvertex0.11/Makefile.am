#* Copyright (c) 2011  by HPC Links 
#* 
#* Permission to use, copy, modify, and distribute this software for any 
#* purpose with or without fee is hereby granted, provided that the above 
#* copyright notice and this permission notice appear in all copies. 
#* 
#* THE SOFTWARE IS PROVIDED "AS IS" AND HPC Links DISCLAIMS ALL WARRANTIES 
#* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF 
#* MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL HPC Links BE LIABLE FOR 
#* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES 
#* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
#* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT 
#* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#* 
#*   HPC Links 
#*   B-8, Second Floor 
#*   May Fair Garden 
#*   New Delhi, India 110016
#Makefile.am for whole vertex

#Author Amjad Syed

AUTOMAKE_OPTIONS = subdir-objects


# etc location

etcdir=$(configfile)/doc
etcprofiledir=/etc/profile.d
etcprofile_SCRIPTS=vexinit/vex.sh

etcsysconfigdir=/etc/sysconfig
etcsysconfig_SCRIPTS=etc/vex



#etc_SCRIPTS=etc/vex.conf etc/namespace.conf

etcinitdir = /etc/init.d

etcinit_SCRIPTS= vexinit/vertex  

utilsdir =$(prefix)/bin

utils_SCRIPTS = utils/clone_sysroot_image   utils/rsync-exclude




AM_LDFLAGS= -lelf  

bin_PROGRAMS =   vexloader/src/vex_loaderbin  vexsched/src/vex_hsched  vexsched/src/vex_client  

bin_SCRIPTS=vexinit/openxrx	vexinit/openxrx_node vexmon/bin/vexmon.sh vexloader/bin/vex_loader






vex_hsched_SOURCES =  vexsched/src/vex_hsched.c

vex_client_SOURCES =  vexsched/src/vex_client.c
SUBDIRS =  xcpu2

computenode-install :
	make -C xcpu2/xcpufs install

	cp vexinit/computeinit/vertex   /etc/init.d
	cp etc/vex  /etc/sysconfig

# Modulear apporach on compute node
	if test -z "`cat /proc/filesystems | grep 9p `" ; then \
	mkdir -p /lib/modules/`uname -r`/updates/kernel/fs/9p ; \
	install -c  9pkernelmodule/Centos/5.6/`arch`/`uname -r`/9p.ko /lib/modules/`uname -r`/updates/kernel/fs/9p/ ; \
	depmod -a       ; \
	else \
	echo "This is 9p enabled kernel" ; \
	fi
install-exec-hook:

# Vrun soft link
	ln -sf $(prefix)/bin/vex_loaderbin /usr/bin/vrun
# Testing if vex.conf exist and if not install it 
	if [ -f $(configfile)/etc/vex.conf ] ; then \
	echo "Vex.conf exists dont overwrite" ; \
	else \
	mkdir -p $(configfile)/etc ; \
	install -c etc/vex.conf $(configfile)/etc ; \
	fi

#Testing if namespace.conf exist if not install it 
	if [ -f $(configfile)/etc/namespace.conf ] ; then \
	echo "Namespace.conf exists dont overwrtie" ; \
	else \
	mkdir -p $(configfile)/etc ; \
	install -c etc/namespace.conf $(configfile)/etc  ; \	
	fi

# Installing and depmoding 9p.ko
#check if this is 9p kernel module
	if test -z "`cat /proc/filesystems | grep 9p `" ; then \
	mkdir -p /lib/modules/`uname -r`/updates/kernel/fs/9p ; \
	install -c  9pkernelmodule/Centos/5.6/`arch`/`uname -r`/9p.ko /lib/modules/`uname -r`/updates/kernel/fs/9p/ ; \
	depmod -a	; \
	else \
	echo "This is 9p enabled kernel" ; \
	fi

prefix-install :
	
	mkdir -p  $(prefix)/bin
	mkdir -p $(prefix)/utils
	mkdir -p $(prefix)/sbin
	cp vexsched/src/vex_hsched      $(prefix)/bin
	cp vexsched/src/vex_client      $(prefix)/bin
	cp vexloader/bin/vex_loader     $(prefix)/bin
	cp vexmon/bin/vexmon.sh         $(prefix)/bin
	cp vexinit/openxrx              $(prefix)/bin
	cp vexinit/openxrx_node         $(prefix)/bin
	cp utils/clone_sysroot_image     $(prefix)/sbin
	cp utils/rsync-exclude     $(prefix)/sbin
	cp xcpu2/xcpufs/xcpufs           $(prefix)/sbin
	cp xcpu2/xcpufs/xcpufs.static    $(prefix)/sbin
	cp xcpu2/utils/xrx               $(prefix)/bin
	cp xcpu2/utils/xgetent           $(prefix)/bin
	cp xcpu2/utils/xk                $(prefix)/bin
	cp xcpu2/utils/xps               $(prefix)/bin
	cp xcpu2/utils/xstat             $(prefix)/bin
	cp xcpu2/utils/xuserset          $(prefix)/bin
	cp xcpu2/utils/xgroupset         $(prefix)/bin
	cp xcpu2/statfs/statfs           $(prefix)/bin
	cp vexloader/src/vex_loaderbin    $(prefix)/bin
	chmod a+x $(prefix)/bin/openxrx

other-install :
	if [ -f $(configfile)/etc/vex.conf ] ; then \	
	echo "Vex.conf already exists dont overwrite" ; \
	else \
	mkdir -p $(configfile)/etc ; \
	install -c  etc/vex.conf $(configfile)/etc; \
	fi
	if [ -f $(configfile)/etc/namespace.conf ] ; then \
	echo " Namespace.conf already exists dont overwrite" ; \
	else \
	mkdir -p $(configfile)/etc ; \
	install -c etc/namespace.conf $(configfile)/etc; \
	fi


	mkdir -p $(configfile)/doc
	install -c etc/vex.conf $(configfile)/doc
	install -c etc/namespace.conf $(configfile)/doc
	install -c etc/vex /etc/sysconfig
	install -c vexinit/vex.sh  /etc/profile.d
	install -c vexinit/vertex /etc/init.d/vertex
	ln -sf $(prefix)/bin/vex_loaderbin  /usr/bin/vrun	

	if test -z "`cat /proc/filesystems | grep 9p `" ; then \
	mkdir -p /lib/modules/`uname -r`/updates/kernel/fs/9p ;\
	install -c 9pkernelmodule/Centos/5.6/`arch`/`uname -r`/9p.ko  /lib/modules/`uname -r`/updates/kernel/fs/9p ; \
	depmod -a ; \
	else \
	echo "This kernel has 9p enabled" ; \
	fi
#uninstall :
#	rm -rf $(prefix)/bin
#	rm -rf $(prefix)/etc
#	rm -rf $(configfile)/doc
#	rm -rf $(prefix)/sbin
#	rm -rf $(prefix)/utils
#	rm -rf /etc/profile.d/vex.sh
##	rm -rf /etc/sysconfig/vex
#
#	rm -rf /etc/init.d/vertex
#	rm -rf /usr/bin/vrun
#	rm -rf $(prefix)/include
#	rm -rf $(prefix)/lib
#	rm -rf $(prefix)/lib64
#	rm -rf $(prefix)
 
