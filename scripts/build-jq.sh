#!/bin/sh

set -exu

cd /jq-*/

apk add build-base clang

apk add autoconf automake libtool
autoreconf -fi

# gcc doesn't work for some reason: `configure: error: C compiler cannot create executables`
export CC=clang

# Disable regular expression support and avoid using flex or bison
./configure --without-oniguruma --disable-maintainer-mode

make -j8 LDFLAGS=-all-static

strip jq

# print out some info about this, size, and to ensure it's actually fully static
ls -lah jq
file jq
# exit with error code 1 if the executable is dynamic, not static
ldd jq && exit 1 || true

./jq -V
echo '{}' | ./jq .

mkdir -p /tmp/release/
mv jq /tmp/release/jq
