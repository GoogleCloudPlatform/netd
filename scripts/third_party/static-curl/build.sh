#!/bin/sh

# to test locally, run one of:
# docker run --rm -v $(pwd):/tmp -w /tmp -e ARCH=amd64 alpine /tmp/build.sh
# docker run --rm -v $(pwd):/tmp -w /tmp -e ARCH=aarch64 multiarch/alpine:aarch64-latest-stable /tmp/build.sh
# docker run --rm -v $(pwd):/tmp -w /tmp -e ARCH=ARCH_HERE ALPINE_IMAGE_HERE /tmp/build.sh

set -exu

cd /curl-*/

# dependencies to build curl
apk add build-base clang openssl-dev groff perl

# these are missing on at least armhf
apk add openssl-libs-static || true

# gcc is apparantly incapable of building a static binary, even gcc -static helloworld.c ends up linked to libc, instead of solving, use clang
export CC=clang

# apply patches if needed
#patch -p1 < ../static.patch
#apk add autoconf automake libtool
#autoreconf -fi
# end apply patches

# set up any required curl options here
#LDFLAGS="-static" PKG_CONFIG="pkg-config --static" ./configure --disable-shared --enable-static --disable-libcurl-option --without-brotli --disable-manual --disable-unix-sockets --disable-dict --disable-file --disable-gopher --disable-imap --disable-smtp --disable-rtsp --disable-telnet --disable-tftp --disable-pop3 --without-zlib --disable-threaded-resolver --disable-ipv6 --disable-smb --disable-ntlm-wb --disable-tls-srp --disable-crypto-auth --without-ngtcp2 --without-nghttp2 --disable-ftp --disable-mqtt --disable-alt-svc --without-ssl

LDFLAGS="-static" PKG_CONFIG="pkg-config --static" ./configure --disable-shared --enable-static \
  --disable-libcurl-option --without-brotli --disable-manual --disable-unix-sockets \
  --disable-dict --disable-file --disable-gopher --disable-imap --disable-smtp \
  --disable-rtsp --disable-telnet -disable-tftp --disable-pop3 --without-zlib \
  --disable-threaded-resolver --enable-ipv6 --disable-smb --disable-ntlm-wb \
  --disable-tls-srp --disable-crypto-auth --without-ngtcp2 --without-nghttp2 \
  --disable-ftp --disable-mqtt --disable-alt-svc --with-ssl --without-libssh2 \
  --disable-ares --disable-cookies --disable-dateparse --disable-dnsshuffle \
  --disable-doh --disable-get-easy-options --disable-hsts --disable-http-auth \
  --disable-netrc --disable-progress-meter --disable-proxy --disable-pthreads \
  --disable-socketpair --disable-versioned-symbols --without-libpsl --without-zstd \
  --without-libidn2 --without-librtmp

make -j4 V=1 LDFLAGS="-static -all-static"

# binary is ~13M before stripping, 2.6M after
strip src/curl

# print out some info about this, size, and to ensure it's actually fully static
ls -lah src/curl
file src/curl
# exit with error code 1 if the executable is dynamic, not static
ldd src/curl && exit 1 || true

./src/curl -V

#./src/curl -v http://www.moparisthebest.com/; ./src/curl -v https://www.moparisthebest.com/ip

# we only want to save curl here
mkdir -p /tmp/release/
mv src/curl "/tmp/release/curl"
