#!/bin/sh

set -u -e

token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
node_url="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/nodes/${HOSTNAME}"
pod_cidr=$(curl -k -s -H "Authorization: Bearer $token" $node_url | jq '.spec.podCIDR')
if [ -z "${pod_cidr:-}" ]; then
  echo "Failed to fetch PodCIDR from K8s API server. Exiting with an error (1) ..."
  exit 1
fi

if [ -w /host/etc/cni/net.d ]; then
  cni_spec=$(echo ${CNI_SPEC_TEMPLATE:-} | sed -e "s#podCidr#${pod_cidr:-}#g")

cat >/host/etc/cni/net.d/$CNI_SPEC_NAME <<EOF
${cni_spec:-}
EOF
echo "Created PTP CNI spec ${CNI_SPEC_NAME}!"
fi
