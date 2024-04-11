export KUBERNETES_SERVICE_HOST=kubernetes.default.svc
export KUBERNETES_SERVICE_PORT=443

export ENABLE_CALICO_NETWORK_POLICY=false
export ENABLE_BANDWIDTH_PLUGIN=false
export ENABLE_CILIUM_PLUGIN=true
export CILIUM_HEALTHZ_PORT=63197
export CILIUM_FAST_START_NAMESPACES=default,kube-system
export ENABLE_MASQUERADE=false
export ENABLE_IPV6=false
export RUN_CNI_WATCHDOG=true

CNI_SPEC_TEMPLATE=$(cat testdata/spec-template-v2.json)
export CNI_SPEC_TEMPLATE

export CNI_SPEC_TEMPLATE_VERSION=2.0

export TEST_WANT_EXIT_CODE=24

function before_test() {

  function curl() {
    # shellcheck disable=SC2317
    case "$*" in
      *http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0*)
        echo '{"ipv6s": ["2600:1900:4000:318:0:7:0:0"]}'
        ;;
      *https://kubernetes.default.svc:443/api/v1/nodes/*)
        echo '{
                "metadata": {
                  "labels": {
                  },
                  "creationTimestamp": "2024-01-03T11:54:01Z",
                  "name": "gke-my-cluster-default-pool-128bc25d-9c94",
                  "resourceVersion": "891003",
                  "uid": "f2353a2f-ca8c-4ca0-8dd3-ad1f964a54f0"
                },
                "spec": {
                  "podCIDR": "10.52.1.0/24",
                  "podCIDRs": [
                    "10.52.1.0/24"
                  ],
                  "providerID": "gce://my-gke-project/us-central1-c/gke-my-cluster-default-pool-128bc25d-9c94"
                }
              }'
        ;;
      *http://localhost:63197/*)
        # With fast-start enabled, CNI config should have been written
        # at the first Cilium health check attempt.
        exit "${TEST_WANT_EXIT_CODE}"
        ;;
      *)
        #unsupported
        exit 1
    esac
  }
  export -f curl

  # shellcheck disable=SC2317
  function sleep() {
    echo "[MOCK called] sleep $*"
    echo "[MOCK] this test expects a delay during fast start."
  }
  export -f sleep

}

function verify() {
  local expected
  local actual

  expected=$(jq -S . <"testdata/expected-cilium-faststart.json")
  actual=$(jq -S . <"/host/etc/cni/net.d/${CNI_SPEC_NAME}")

  if [ "$expected" != "$actual" ] ; then
    echo "Expected cni_spec value:"
    echo "$expected"
    echo "but actual was"
    echo "$actual"
    return 1
  fi

}
