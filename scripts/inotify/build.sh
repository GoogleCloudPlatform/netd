#!/bin/sh

set -exu

cd /inotify

apk add build-base clang

# gcc doesn't work for some reason: `configure: error: C compiler cannot create executables`
export CC=clang

${CC} -static inotify.c -o inotify

strip inotify

# print out some info about this, size, and to ensure it's actually fully static
ls -lah inotify
file inotify
# exit with error code 1 if the executable is dynamic, not static
ldd inotify && exit 1 || true

./test.sh

mkdir -p /tmp/release/
mv inotify /tmp/release/inotify
