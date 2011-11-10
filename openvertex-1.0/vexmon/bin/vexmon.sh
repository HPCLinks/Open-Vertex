#!/bin/bash
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
# ---------------------------------------------------------------------------------
#
#  vexmon.sh: This is the vex resource availability deamon
#
#  Every $sleeptime seconds this routine wakes up and checks three things
# 1.  for each active resource 
#        if process is not active then 
#           free the resource  (./vex_client -f pid:$pid) 
# 2.  for each failed nodes 
#        if node is now available then 
#            free the node (./vex_client  -f node:$node)
# 3.  for each schedulable node
#        if node is not operational then
#           remove from schedulable resource (./vex_client -b node:$node)
#
#  Author: Greg Rodgers
#
# ---------------------------------------------------------------------------------

ARCH=`uname -p`
VEXSCHEDBIN="${VEXHOME}/bin/vex_client"
VEXOPENXRX="${VEXHOME}/bin/openxrx_node"
RSRVWORD="RESERVED"
AVAILWORD="AVAIL"
sleeptime=30

while [ 1 ] ; do 

#  Make sure all active processes are running on the vertex node
   busylist=`${VEXSCHEDBIN} -l `
   for pid in $busylist ; do 
      ps --noheader v $pid 2>/dev/null 1>/dev/null
      if [ $? != 0 ] ; then 
         echo vexmon.sh: ${VEXSCHEDBIN} -f pid:$pid
         ${VEXSCHEDBIN} -f pid:$pid
      fi
   done

#  Now see if any reserved nodes are back online
   faillist=`${VEXSCHEDBIN} -n | grep "$RSRVWORD" | cut -d: -f2 `
   for node in $faillist ; do 
      ping -c1 -W1  $node >/dev/null 2>/dev/null
      if [ $? == 0 ] ; then 
      # OK, the node pings
      # Now, we need to use xcpu to check if node is really ready for xcpu work
      # before adding.
      # FIXME: FOR NOW WE JUST BLINDLY ADD THE NODE IF IT PINGS
             $VEXOPENXRX $node >/dev/null 2>/dev/null
             echo vexmon.sh: ${VEXSCHEDBIN} -f node:$node 
             ${VEXSCHEDBIN} -f node:$node >/dev/null
      fi
   done

#  nodes deleted from faillist above will be have their availability double checked 
   availlist=`${VEXSCHEDBIN} -n | grep "$AVAILWORD" | cut -d: -f2 `
   for node in $availlist ; do 
      ping -c1  $node >/dev/null 2>/dev/null
      if [ $? != 0 ] ; then 
         # node failed to ping so do not even attempt xcpu test
         echo vexmon.sh: ${VEXSCHEDBIN} -b node:$node 
         ${VEXSCHEDBIN} -b node:$node >/dev/null
      fi
   done

   echo "SLEEPING FOR $sleeptime SECONDS "
   sleep $sleeptime

done
