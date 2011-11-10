#!/bin/bash
#
# chkconfig: 345 75 25
# description: Starts master on one port, using config files in /etc/sysconfig/xget
#

source /etc/rc.d/init.d/functions
XGET=/usr/sbin/xget
XGET_CONFIG=/etc/sysconfig/xget

[ -f $XGET_CONFIG ] || exit 1

. $XGET_CONFIG

[ -z $PORT ] && echo "Port not specified" && exit 1
[ -z $SRC ] && echo "Source not specified" && exit 1
[ -z $DEBUG ] && DEBUG=0
[ ! -x $XGET ] && echo "$XGET is not installed" && exit 1

case "$1" in
    start)
    
        echo -n $"Starting Xget: "
        daemon $XGET -D $DEBUG -p $PORT $SRC 
        RETVAL=$?
        echo
        [ $RETVAL -eq 0 ] && touch /var/lock/subsys/xget || RETVAL=1
        ;;    
    stop)
        echo -n "Stopping Xget: "
        killproc $XGET
        RETVAL=$?
	echo
        [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/xget
        ;;
    restart)
        $0 stop
        RETVAL=$?
        [ $RETVAL -eq 0 ] && $0 start
        RETVAL=$?
        ;;
    status)
        status $XGET
        RETVAL=$?
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
esac

exit $RETVAL
