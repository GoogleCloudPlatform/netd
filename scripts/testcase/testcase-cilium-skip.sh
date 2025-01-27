export KUBERNETES_SERVICE_HOST=kubernetes.default.svc
export KUBERNETES_SERVICE_PORT=443

export ENABLE_CALICO_NETWORK_POLICY=false
export ENABLE_CILIUM_PLUGIN=true
export CILIUM_HEALTHZ_PORT=63197
export CILIUM_FAST_START_NAMESPACES=
export ENABLE_MASQUERADE=false
export ENABLE_IPV6=false

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
                    "cloud.google.com/gke-dpv2-unified-cni": "true"
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
      *http://localhost:63197/*)
        echo 'healthz'
        ;;
      *)
        #unsupported
        exit 1
    esac
  }
  export -f curl

  rm -f "/host/etc/cni/net.d/${CNI_SPEC_NAME}"

}

function verify() {
  local actual

  if [[ -f "/host/etc/cni/net.d/${CNI_SPEC_NAME}" ]]; then
    actual=$(jq -S . <"/host/etc/cni/net.d/${CNI_SPEC_NAME}")
    echo "Expected CNI config to be missing, but it has:"
    echo "$actual"
    return 1
  fi

}
