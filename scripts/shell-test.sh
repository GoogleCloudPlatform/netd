#!/bin/bash
# shellcheck disable=SC2015

FAIL_COUNT=0

run_test() {
  echo -n "Running test [$1]:"
}

pass() {
  echo " PASS"
}

fail() {
  echo " FAILED"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

run_test test_cmd
[ -d / ] && pass || fail

run_test sleep_cmd
sleep 1 && pass || fail

run_test curl_cmd
[[ "$(curl -sw '%{response_code}' https://www.google.com/generate_204)" == '204' ]] && pass || fail

run_test ipv4_subnet
# shellcheck disable=SC2050
[[ '"10.0.0.0/8"' =~ ^\"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/[0-9][0-9]*\"$ ]] && pass || fail

run_test iptables_cmd_exists
# Cannot simply run iptables when the platform doesn't match (QEMU used):
# iptables/1.8.7 Failed to initialize nft: Protocol not supported
[[ -x /usr/sbin/iptables ]] && pass || fail

run_test ip6tables_cmd_exists
# Cannot simply run ip6tables when the platform doesn't match (QEMU used):
# ip6tables/1.8.7 Failed to initialize nft: Protocol not supported
[[ -x /usr/sbin/ip6tables ]] && pass || fail

run_test grep_cmd
(echo netd-test | grep test >/dev/null) && pass || fail

if ! grep -q qemu /proc/1/cmdline; then
  # If not running inside QEMU:

  run_test iptables_cmd
  iptables -V >/dev/null && pass || fail

  run_test ip6tables_cmd
  ip6tables -V >/dev/null && pass || fail
fi

run_test jq_cmd
[[ "$(echo '{"test":"value"}' | jq .test)" == '"value"' ]] && pass || fail

run_test inotify_cmd
inotify / '' /bin/cat /dev/null >/dev/null && pass || fail

run_test default_nic_mtu
[[ -f "/sys/class/net/$(route -n | grep -E '^0\.0\.0\.0\s+\S+\s+0\.0\.0\.0' | sort -n -k5,5 | grep -oE '\S+$')/mtu" ]] && pass || fail

run_test sort_cmd
[[ "$(echo $'A 11\nB 2' | sort -n -k2,2)" == $'B 2\nA 11' ]] && pass || fail

run_test mktemp_cmd
[[ -f "$(mktemp /tmp.XXXXXX)" ]] && pass || fail

run_test mv_cmd
echo >/netd-test && mv /netd-test /netd-test-moved && [[ -f /netd-test-moved ]] && pass || fail

run_test rm_cmd
echo >/netd-test && rm /netd-test && [[ ! -f /netd-test ]] && pass || fail

run_test timeout_cmd
timeout 2s sleep 1s && pass || fail

run_test sleep_infinity_cmd
timeout 1s sleep infinity && fail || { [[ "$?" == 124 ]] && pass || fail; }

run_test base64_cmd
[[ "$(echo -n AAA | base64 -w 0)" == QUFB ]] && pass || fail

exit $FAIL_COUNT
