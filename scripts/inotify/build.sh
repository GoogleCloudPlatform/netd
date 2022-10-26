#!/bin/sh

set -exu

cd /inotify

apk add build-base clang

# gcc doesn't work for some reason: `configure: error: C compiler cannot create executables`
export CC=clang

${CC} -Wall -Wextra -Werror -O2 -static inotify.c -o inotify

strip inotify

# print out some info about this, size, and to ensure it's actually fully static
ls -lah inotify
file inotify
# exit with error code 1 if the executable is dynamic, not static
ldd inotify && exit 1 || true

# quick test; full test in ./test.sh
./inotify / '' /bin/true

mkdir -p /tmp/release/
# cp instead of mv so we can run ./test.sh later
cp inotify /tmp/release/inotify
