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
#                                               -*- Autoconf -*-M_C
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(vertex, 0.10, openvertex@googlegroups.com)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([vexloader/src/vex_loaderbin.c])
AC_CONFIG_HEADER([config.h])
#AM_OUTPUT_FILES
# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_YACC
AC_PROG_CC
AC_PROG_LEX
#AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AM_PROG_CC_C_O
#ck to check for 9p kernel rpm is installed or not
AC_MSG_CHECKING( [checking for 9p support in kernel ] )
if test -z "`cat /proc/filesystems | grep 9p `"
then
#AC_MSG_ERROR( [ 9p support is not there in kernel ] )
#check for 9p kernel module is installed 
AC_MSG_CHECKING( [ kernel version support for 9p kernel module ] )
kernel=`uname -r`
echo $kernel

if test $kernel != "2.6.18-238.12.1.el5" && test  $kernel != "2.6.18-194.17.1.el5"
then
AC_MSG_ERROR( [ This kernel version is not  supported please send email to :openvertexgooglegroups.com ])
else
AC_MSG_NOTICE([ This kernel version is supported ])
fi

else
AC_MSG_NOTICE([kernel with 9p support is installed ] )
fi

#check for 9p kernel module is installed if not error else install it

#AC_MSG_CHECKING( [kernel version support for 9p kernel module ] )
#kernel=`uname -r`
#echo $kernel

#if  test $kernel != "2.6.18-238.12.1.el5"   &&   test $kernel != "2.6.18-194.17.1.el5" 
#then
#AC_MSG_ERROR( [ This kernel version is not supported please send email to : openvertex@googlegroups.com ])
#else
#AC_MSG_NOTICE([ This kernel version is supported ])
#fi





#hack for dhcp server 

AC_MSG_CHECKING( [  dhcp server ] )
if  test ! -f /etc/dhcpd.conf 
then
AC_MSG_ERROR([ dhcp server is not installed ] )
else
AC_MSG_NOTICE([ dhcp server is installed ])
fi


#check for VEXHOM env variable
#echo $prefix
#Making /usr/local/vertex as defaut location
AC_PREFIX_DEFAULT(/usr/local/vertex)

#AC_MSG_CHECKING( [ VEXHOME environment variable  ] )

#if test  -z "`  printenv | grep  VEXHOME `"  
#then
#AC_MSG_ERROR( [ Please have your system admin setup VEXHOME environment variable ] )
#else
#AC_MSG_NOTICE( [ VEXHOME is set  ] )
#fi



#Disabling all lib checks checks done my require in rpm spec
# Checks for libraries.
# FIXME: Replace `main' with a function in `-lbusybox':
#AC_CHECK_LIB([busybox], [main])
# FIXME: Replace `main' with a function in `-lcrypt':
#AC_CHECK_LIB([crypt], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
#AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-lcurses':
#AC_CHECK_LIB([curses], [main])
# FIXME: Replace `main' with a function in `-ldl':
#AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lelf':
#AC_CHECK_LIB([elf], [main])
# FIXME: Replace `main' with a function in `-letpan':
#AC_CHECK_LIB([etpan], [main])
# FIXME: Replace `main' with a function in `-lgphoto2':
#AC_CHECK_LIB([gphoto2], [main])
# FIXME: Replace `main' with a function in `-libverbs':
#AC_CHECK_LIB([ibverbs], [main])
# FIXME: Replace `main' with a function in `-lm':
#AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-lncurses':
#AC_CHECK_LIB([ncurses], [main])
# FIXME: Replace `main' with a function in `-lnpclient':
#AC_CHECK_LIB([npclient], [main])
# FIXME: Replace `main' with a function in `-lnpfs':
#AC_CHECK_LIB([npfs], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB(aio, main,[AC_MSG_NOTICE([libaio-devel is installed])],[AC_MSG_ERROR([Please install libaio-devel])])
# FIXME: Replace `main' with a function in `-lrdmacm':
#AC_CHECK_LIB([rdmacm], [main])
# FIXME: Replace `main' with a function in `-lsasl2':
#AC_CHECK_LIB([sasl2], [main])
# FIXME: Replace `main' with a function in `-lspclient':
#AC_CHECK_LIB([spclient], [main])
# FIXME: Replace `main' with a function in `-lspfs':
#AC_CHECK_LIB([spfs], [main])
# FIXME: Replace `main' with a function in `-lssl':
#AC_CHECK_LIB([ssl], [main])
# FIXME: Replace `main' with a function in `-lstrutil':
#AC_CHECK_LIB([strutil], [main])
# FIXME: Replace `main' with a function in `-lxauth':
#AC_CHECK_LIB([xauth], [main])
# FIXME: Replace `main' with a function in `-lxcpu':
#AC_CHECK_LIB([xcpu], [main])
#Addding support for IDMETHOD 
#HAck to ask user to install libaio-devel, this should really be CHECK_LIB FUNC

#AC_CHECK_FILES(/usr/lib/libaio.a /usr/lib64/libaio.a ,[AC_MSG_NOTICE([libaio-devel is installed ])] ,[AC_MSG_ERROR([ Please install libaio-devel package ])])

AC_ARG_ENABLE([computeonly],AS_HELP_STRING([--enable-computeonly    enables xcpufs build on computenode ]))


AC_ARG_WITH([uidmethod],[AC_HELP_STRING([--with-uidmethod      choose  user id method local or yp  default is local,  [default=local]])],[uidmethod=$withval],[uidmethod=local])
echo $uidmethod

AC_SUBST([uidmethod])

AC_ARG_WITH([configfile],[AC_HELP_STRING([--with-configfile   choose location of config file default is /var/vertex, [default=/var/vertex]])],[configfile=$withval],[configfile=/var/vertex])

echo $configfile

AC_SUBST([configfile])
AC_ARG_WITH([sysrootfile],[AC_HELP_STRING([--with-sysrootfile   choose location of sysroot default is /var/vertex/SYSROOT, [default=/var/vertex/SYSROOT]])],[sysrootfile=$withval],[sysrootfile=/var/vertex/SYSROOT])

AC_SUBST([sysrootfile])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_MAJOR
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h locale.h mntent.h netdb.h netinet/in.h paths.h shadow.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/mount.h sys/param.h sys/socket.h sys/statfs.h sys/statvfs.h sys/time.h sys/vfs.h syslog.h termios.h unistd.h utime.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_STRUCT_TM
AC_C_VOLATILE
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_REPLACE_FNMATCH
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_GETMNTENT
AC_FUNC_GETPGRP
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
#AC_TGGYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRCOLL
AC_FUNC_STRERROR_R
AC_FUNC_STRFTIME
AC_FUNC_STRNLEN
AC_FUNC_STRTOD
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS([alarm atexit dup2 endgrent endpwent ftruncate getcwd gethostbyaddr gethostbyname gethostname getmntent getmntinfo getpagesize getspnam gettimeofday getusershell hasmntopt inet_ntoa isascii lchown localtime_r memchr memmove mempcpy memset mkdir mkfifo munmap pow putenv realpath regcomp rmdir select setenv sethostname setlocale socket sqrt stime stpcpy strcasecmp strchr strcspn strdup strerror strncasecmp strndup strpbrk strrchr strspn strstr strtol strtoul strtoull sysinfo tzset uname utime utmpname])

#Compute node option only





AC_CONFIG_FILES([Makefile
                 etc/vex
								 vexinit/vex.sh
								 xcpu2/libstrutil/Makefile
								 xcpu2/libxcpu/Makefile
								 xcpu2/libxauth/Makefile 
								 xcpu2/spfs/libspfs/Makefile
								 xcpu2/spfs/libspclient/Makefile
								 xcpu2/spfs/fs/Makefile 
								 xcpu2/spfs/Makefile
								 xcpu2/npfs/libnpfs/Makefile
								 xcpu2/npfs/libnpclient/Makefile
								 xcpu2/npfs/fs/Makefile
								 xcpu2/npfs/Makefile
								 xcpu2/statfs/Makefile
								 xcpu2/utils/Makefile
								 xcpu2/xcpufs/Makefile
								 xcpu2/Makefile ])

#AC_OUTPUT([etc/vex.sh])
AC_OUTPUT

