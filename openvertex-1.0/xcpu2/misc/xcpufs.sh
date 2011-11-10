#!/bin/bash
#
# chkconfig: 345 75 25
# description: Exports a 9PFS view of a node for use with the xcpu cluster management software.
#

source /etc/rc.d/init.d/functions

XCPUFS=/usr/sbin/xcpufs

RETVAL=0

if [ ! -f $XCPUFS ] ; then
    echo "The xcpufs service is not installed."
    exit 1
fi

case "$1" in
    start)
        echo -n "Starting xcpufs: "
        daemon $XCPUFS
        RETVAL=$?
        echo
        [ $RETVAL -eq 0 ] && touch /var/lock/subsys/xcpufs
        ;;
    stop)
        echo -n "Stopping xcpufs: "
        killproc $XCPUFS
        RETVAL=$?
	echo
        [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/xcpufs
        ;;
    restart)
        $0 stop
        RETVAL=$?
        [ $RETVAL -eq 0 ] && $0 start
        RETVAL=$?
        ;;
    status)
        status $XCPUFS
        RETVAL=$?
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
esac

exit $RETVAL
