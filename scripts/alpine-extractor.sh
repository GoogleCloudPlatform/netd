#!/bin/sh

apk add "$@"

mkdir -p /tmp/extras/lib/apk/db

mkdir -p /tmp/extras/LICENSES.alpine

for pkg in "$@"
do
  # Package info for vulnerability scanner
  {
    echo "P:$pkg"
    grep "^P:$pkg$" -A 2147483647 /lib/apk/db/installed | grep '^V:' | head -n 1
    echo
  } >> /tmp/extras/lib/apk/db/installed

  # Package license for compliance
  license=$(grep "^P:$pkg$" -A 2147483647 /lib/apk/db/installed | grep '^L:' | head -n 1 | cut -d: -f2-)
  wget "https://raw.githubusercontent.com/spdx/license-list-data/master/text/$license.txt" -O "/tmp/extras/LICENSES.alpine/$pkg"
done
