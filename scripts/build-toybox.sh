#!/bin/sh

set -exu

# Toybox route is "pending" but the TODOs are in add/del;
# we're using it for display only so we should be good.
# Toybox sh has more TODOs in multiple areas so don't use it.
toys="base64 mktemp mv timeout"

cd /toybox-*/

apk add build-base clang bash linux-headers

# gcc doesn't work for some reason: `configure: error: C compiler cannot create executables`
export CC=clang

make allnoconfig

for toy in $toys
do
  toy_upper=$(echo "$toy" | tr '[:lower:]' '[:upper:]')
  echo "CONFIG_${toy_upper}=y" >> .config
done

LDFLAGS="--static" make

# print out some info about this, size, and to ensure it's actually fully static
ls -lah toybox
file toybox
# exit with error code 1 if the executable is dynamic, not static
ldd toybox && exit 1 || true

./toybox
./toybox timeout 1s ./toybox

mkdir -p /tmp/release/
mv toybox /tmp/release/toybox

chmod a+rx /tmp/release/toybox

for cmd in $toys
do
  ln -s /bin/toybox "/tmp/release/$cmd"
done
