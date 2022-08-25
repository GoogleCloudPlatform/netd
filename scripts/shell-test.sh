#!/bin/bash
#

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

run_test ls_cmd
[[ -n "$(ls /)" ]] && pass || fail

run_test sleep_cmd
sleep 1 && pass || fail

run_test sed_cmd
[[ "$(echo "cfg1:@val,cfg2:ok" | sed -e "s#@val#test#g")" == "cfg1:test,cfg2:ok" ]] && pass || fail

run_test curl_cmd
[[ "$(curl -s -k -H "Header: netd-test" https://httpbin.org/headers)" =~ netd-test ]] && pass || fail

run_test ipv4_subnet
[[ '"10.0.0.0/8"' =~ ^\"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/[0-9][0-9]*\"$ ]] && pass || fail

run_test iptables_cmd
# Cannot simply run iptables when the platform doesn't match (QEMU used):
# iptables/1.8.7 Failed to initialize nft: Protocol not supported
#iptables -V >/dev/null && pass || fail
[[ -x /usr/sbin/iptables ]] && pass || fail

run_test ip6tables_cmd
# Cannot simply run ip6tables when the platform doesn't match (QEMU used):
# ip6tables/1.8.7 Failed to initialize nft: Protocol not supported
#ip6tables -V >/dev/null && pass || fail
[[ -x /usr/sbin/ip6tables ]] && pass || fail

run_test grep_cmd
(echo netd-test | grep test >/dev/null) && pass || fail

run_test jq_cmd
[[ "$(echo '{"test":"value"}' | jq .test)" == '"value"' ]] && pass || fail

run_test default_nic_mtu
[[ -f "/sys/class/net/$(route -n | grep -E '^0\.0\.0\.0\s+\S+\s+0\.0\.0\.0' | grep -oE '\S+$')/mtu" ]] && pass || fail

run_test mktemp_cmd
[[ -f "$(mktemp /tmp.XXXXXX)" ]] && pass || fail

run_test mv_cmd
echo >/netd-test && mv /netd-test /netd-test-moved && [[ -f /netd-test-moved ]] && pass || fail

run_test rm_cmd
echo >/netd-test && rm /netd-test && [[ ! -f /netd-test ]] && pass || fail

exit $FAIL_COUNT
