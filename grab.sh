#!/bin/sh

# usage example:
#   ./grab.sh vpopmail 5.4.18
#
# downloads vpopmail tagged with v5_4_18 from SourceForge
# builds vpopmail-5.4.18.tar.gz

app=$1
ver=$2
sfuser="tomcollins"
tag=`echo $ver | sed s/\\\./_/g`

echo "grabbing $app with tag v$tag"
cvs -d:ext:$sfuser@$app.cvs.sf.net:/cvsroot/$app export -r v$tag $app

touch $app/Make* $app/config* $app/ac*
mv $app $app-$ver

echo "building $app-$ver.tar.gz"
tar czvf $app-$ver.tar.gz $app-$ver
