#!/bin/sh

# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -u -e

echo "netd version: @VERSION@"

if [ "${ENABLE_CALICO_NETWORK_POLICY}" == "true" ]; then
  echo "Calico Network Policy is enabled by ENABLE_CALICO_NETWORK_POLICY. Generating Calico CNI spec."
  cni_spec=${CALICO_CNI_SPEC_TEMPLATE}
else
  cni_spec=${CNI_SPEC_TEMPLATE}
fi


token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
node_url="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/nodes/${HOSTNAME}"
ipv4_subnet=$(curl -k -s -H "Authorization: Bearer $token" $node_url | jq '.spec.podCIDR')
if [ -z "${ipv4_subnet:-}" ]; then
  echo "Failed to fetch PodCIDR from K8s API server. Exiting with an error (1) ..."
  exit 1
fi

if [ -w /host/etc/cni/net.d ]; then
  echo "Adding IPV4 subnet range ${ipv4_subnet:-}."
  cni_spec=$(echo ${cni_spec:-} | sed -e "s#@ipv4Subnet#[{\"subnet\": ${ipv4_subnet:-}}]#g")

  if [ "$ENABLE_PRIVATE_IPV6_ACCESS" == "true" ]; then
    node_ipv6_addr=$(curl -s -k --fail "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/?recursive=true" -H "Metadata-Flavor: Google" | jq -r '.ipv6s[0]' ) ||:

    if [ -n "${node_ipv6_addr:-}" ] && [ "${node_ipv6_addr}" != "null" ]; then
      echo "Found IPV6 address assignment ${node_ipv6_addr:-}."
      cni_spec=$(echo ${cni_spec:-} | sed -e \
        "s#@ipv6SubnetOptional#, [{\"subnet\": \"${node_ipv6_addr:-}/112\"}]#g;
         s#@ipv6RouteOptional#, {\"dst\": \"::/0\"}#g")
    else
      echo "Found empty IPV6 address assignment. Skipping IPV6 subnet and range configuration."
      cni_spec=$(echo ${cni_spec:-} | \
        sed -e "s#@ipv6SubnetOptional##g; s#@ipv6RouteOptional##g")
    fi
  else
    echo "Disabling IPV6 subnet and range configuration. Set ENABLE_PRIVATE_IPV6_ACCESS=true to configure IPV6."
    cni_spec=$(echo ${cni_spec:-} | \
      sed -e "s#@ipv6SubnetOptional##g; s#@ipv6RouteOptional##g")
  fi

cat >/host/etc/cni/net.d/$CNI_SPEC_NAME <<EOF
${cni_spec:-}
EOF

echo "Created PTP CNI spec ${CNI_SPEC_NAME}!"

else
  echo "Could not find writable directory /etc/cni/net.d, which is expected to be mounted at /host/etc/cni/net.d. Exiting with error(2)."
  exit 2
fi
