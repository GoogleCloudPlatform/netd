export KUBERNETES_SERVICE_HOST=kubernetes.default.svc
export KUBERNETES_SERVICE_PORT=443

export ENABLE_CALICO_NETWORK_POLICY=false
export ENABLE_CILIUM_PLUGIN=false
export ENABLE_MASQUERADE=false
export ENABLE_IPV6=false
export SYS_CLASS_NET=/tmp/mock-sys_class_net

CNI_SPEC_TEMPLATE=$(cat testdata/spec-template.json)
export CNI_SPEC_TEMPLATE

function before_test() {

  # shellcheck disable=SC2329
  function curl() {
    # shellcheck disable=SC2317
    case "$*" in
      *http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0*)
        echo '{"ipv6s": ["2600:1900:4000:318:0:7:0:0"]}'
        ;;
      *https://kubernetes.default.svc:443/api/v1/nodes*)
        echo '{"object":{
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
              }}'
        ;;
      *)
        #unsupported
        exit 1
    esac
  }
  export -f curl

  # shellcheck disable=SC2329
  function route() {
    # shellcheck disable=SC2317
    echo 'Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.17.0.1      0.0.0.0         UG    1000   0        0 ens1
0.0.0.0         172.17.0.1      0.0.0.0         UG    999    0        0 ens2
0.0.0.0         172.17.0.1      255.0.0.0       UG    10     0        0 ens3'
  }
  export -f route

  rm -rf "${SYS_CLASS_NET}"
  mkdir -p "${SYS_CLASS_NET}/ens1"
  mkdir -p "${SYS_CLASS_NET}/ens2"
  mkdir -p "${SYS_CLASS_NET}/ens3"
  echo 1461 >"${SYS_CLASS_NET}/ens1/mtu"
  echo 1462 >"${SYS_CLASS_NET}/ens2/mtu"
  echo 1463 >"${SYS_CLASS_NET}/ens3/mtu"

}

function verify() {
  local expected
  local actual

  expected=$(jq -S . <"testdata/expected-mtu.json")
  actual=$(jq -S . <"/host/etc/cni/net.d/${CNI_SPEC_NAME}")

  if [ "$expected" != "$actual" ] ; then
    echo "Expected cni_spec value:"
    echo "$expected"
    echo "but actual was"
    echo "$actual"
    return 1
  fi

}
