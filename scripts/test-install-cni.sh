#!/bin/bash

function init_default_cmd_mocks() {
  shopt -s expand_aliases

  # shellcheck disable=SC2329
  function iptables() {
    # shellcheck disable=SC2317
    echo "[MOCK called] iptables $*"
  }
  export -f iptables

  # shellcheck disable=SC2329
  function ip6tables() {
    # shellcheck disable=SC2317
    echo "[MOCK called] ip6tables $*"
  }
  export -f ip6tables

  # shellcheck disable=SC2329
  function inotify() {
    # shellcheck disable=SC2317
    echo "[MOCK called] inotify $*"
  }
  export -f inotify

  # shellcheck disable=SC2329
  function route() {
    # shellcheck disable=SC2317
    echo 'Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.17.0.1      0.0.0.0         UG    100    0        0 ens0'
  }
  export -f route

  # shellcheck disable=SC2329
  function curl() {
    # shellcheck disable=SC2317
    echo "[MOCK called] curl $*"
  }
  export -f curl

  # shellcheck disable=SC2329
  function timeout() {
    # shellcheck disable=SC2317
    echo "[MOCK called] timeout $*"
  }
  export -f timeout

  # shellcheck disable=SC2317,SC2329
  function sleep() {
    echo "[MOCK called] sleep $*"
    echo "[MOCK] sleep shouldn't be called during normal execution; exiting with ${TEST_EXIT_CODE_SLEEP} as a signal."
    exit "${TEST_EXIT_CODE_SLEEP}"
  }
  export -f sleep

  function before_test() {
    echo "no custom init defined for testcase ${testcase}; define custom mocks in before_test() function as needed"
  }
}

function cleanup_envs() {
  export -n KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT

  export -n \
    CALICO_CNI_SPEC_TEMPLATE_FILE \
    CALICO_CNI_SPEC_TEMPLATE \
    CILIUM_FAST_START_NAMESPACES \
    CILIUM_HEALTHZ_PORT \
    CILIUM_HEALTH_MAX_WAIT_TIME \
    CILIUM_WATCHDOG_FAILURE_RETRY \
    CILIUM_WATCHDOG_SUCCESS_WAIT \
    CNI_SPEC_IPV6_ROUTE \
    CNI_SPEC_TEMPLATE \
    ENABLE_BANDWIDTH_PLUGIN \
    ENABLE_CALICO_NETWORK_POLICY \
    ENABLE_CILIUM_PLUGIN \
    ENABLE_IPV6 \
    ENABLE_MASQUERADE \
    ISTIO_CNI_CONFIG \
    MIGRATE_TO_DPV2 DPV2_MIGRATION_READY \
    RETRY_MAX_TIME \
    RUN_CNI_WATCHDOG \
    STACK_TYPE \
    WRITE_CALICO_CONFIG_FILE \
    IPV6_FORWARDING_CONF \
    CNI_SPEC_TEMPLATE_VERSION
}

export TEST_EXIT_CODE_SLEEP=42

FAIL_COUNT=0

run_test() {
  echo -n "Running test [$1]:"
}

pass() {
  echo " PASS [$*]"
}

fail() {
  echo " FAILED [$*]"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

# shellcheck disable=SC2188
>test.log
for testcase in testcase/testcase-*.sh ; do

  run_test "$testcase"
  echo "======================================" >>test.log
  echo "Log of test invocation for ${testcase}" >>test.log
  # resetting mocks to default before each test
  init_default_cmd_mocks
  # resetting envs
  cleanup_envs

  # allow being overridden in testcase
  TEST_WANT_EXIT_CODE=0

  # setting CNI_SPEC_NAME to testcase name (filename in test.out/)
  CNI_SPEC_NAME="${testcase%.sh}"
  export CNI_SPEC_NAME="${CNI_SPEC_NAME##*/}"
  # loading testcase
  # shellcheck disable=SC1090 source-path=testcase
  . "$testcase"

  # initializing testcase mocks
  before_test

  # running install-cni script
  ./install-cni.sh >>test.log 2>&1
  exit_code="$?"
  if [ "${TEST_WANT_EXIT_CODE}" != "${exit_code}" ] ; then
    # script exited with non-zero code
    fail "unexpected exit code ($exit_code) want (${TEST_WANT_EXIT_CODE})"
  # running testcase verification
  elif ! verify ; then
    fail "verification failure"
  else
    pass "${exit_code}"
  fi

done

echo "Test execution log available in test.log"
exit $FAIL_COUNT
