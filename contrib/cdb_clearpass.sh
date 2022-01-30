#!/bin/bash
#
# This script is for sites prior to 5.0 which use
# the cdb module and want to now support clear
# text passwords. Run the script and it will
# add a trailing ":" colon to each line in vpasswd.
# Next time they set thier password the clear text
# password will be stored.
#

DOMAINSDIR="/home/vpopmail/domains"
VPOPMAILBIN="/home/vpopmail/bin"

for i in `ls $DOMAINSDIR` ; do
        VPASSWD="$DOMAINSDIR/$i/vpasswd"
        if [ -f "$VPASSWD" ] ; then
                echo "converting $i ..."
                for v in `cat $VPASSWD | awk -F: '{ print $1 }'` ; do
                        $VPOPMAILBIN/vmoduser -C "" $v@$i
                done
        fi
done
