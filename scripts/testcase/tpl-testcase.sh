# Template of testcase file
# Each testcase file must have a format of "testcase-{suffix}.sh"

# envs setup
export KUBERNETES_SERVICE_HOST=kubernetes.default.svc
export KUBERNETES_SERVICE_PORT=443

export ENABLE_CALICO_NETWORK_POLICY=false
export ENABLE_BANDWIDTH_PLUGIN=false
export ENABLE_CILIUM_PLUGIN=false
export ENABLE_MASQUERADE=false
export ENABLE_IPV6=false

export CNI_SPEC_TEMPLATE='{}'

# Method to be invoked before install-cni.sh call
# You can configure required mocks here
function before_test() {

  # mocking example of curl call
  function curl() {
    case "$*" in
      *http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0*)
        # call to GCE metadata server
        echo '{}'
        ;;
      *https://kubernetes.default.svc:443/api/v1/nodes/*)
        # call to kube-apiserver
        echo '{}'
        ;;
      *)
        # unmatched call
        exit 1
    esac
  }
  export -f curl

}

# Returns 0 on verification success, non-zero otherwise
function verify() {
  # put verification logic here
  return 0 #success
}
