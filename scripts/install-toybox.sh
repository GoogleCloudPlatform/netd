#!/bin/bash

chmod a+rx /bin/toybox

for cmd in [ ls mktemp mv route sed
do
  ln -s /bin/toybox "/bin/$cmd"
done

rm -f "$0"
