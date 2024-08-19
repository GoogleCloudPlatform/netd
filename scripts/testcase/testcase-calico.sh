export KUBERNETES_SERVICE_HOST=kubernetes.default.svc
export KUBERNETES_SERVICE_PORT=443

export ENABLE_CALICO_NETWORK_POLICY=true
export ENABLE_CILIUM_PLUGIN=false
export ENABLE_MASQUERADE=false
export ENABLE_IPV6=true
export CNI_SPEC_IPV6_ROUTE="{\"dst\": \"2600:1900:4000::/42\"}"
export CNI_SPEC_NAME="10-calico.conflist.template"
export CALICO_CNI_SERVICE_ACCOUNT="calico-cni-sa"
export WRITE_CALICO_CONFIG_FILE=true
export IPV6_FORWARDING_CONF=/tmp/mock-calico-enable-forwarding

CNI_SPEC_TEMPLATE=$(cat testdata/calico-spec-template.json)
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

}

function verify() {
  local expected
  local actual

  expected=$(jq -S . <"testdata/expected-calico.json")
  actual=$(jq -S . <"/host/etc/cni/net.d/10-calico.conflist.template")

  if [ "$expected" != "$actual" ] ; then
    echo "Expected cni_spec value:"
    echo "$expected"
    echo "but actual was"
    echo "$actual"
    return 1
  fi

}
