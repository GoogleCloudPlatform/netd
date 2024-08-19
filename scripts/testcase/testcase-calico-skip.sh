export KUBERNETES_SERVICE_HOST=kubernetes.default.svc
export KUBERNETES_SERVICE_PORT=443

export ENABLE_CALICO_NETWORK_POLICY=true
export ENABLE_CILIUM_PLUGIN=false
export ENABLE_MASQUERADE=false
export ENABLE_IPV6=false

CNI_SPEC_TEMPLATE=$(cat testdata/spec-template.json)
export CNI_SPEC_TEMPLATE

function before_test() {
  true
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
