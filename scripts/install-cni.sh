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

# Get CNI spec template if needed.
if [ "${ENABLE_CALICO_NETWORK_POLICY}" == "true" ]; then
  echo "Calico Network Policy is enabled"
  if [ -z "${CALICO_CNI_SPEC_TEMPLATE_FILE:-}" ]; then
    echo "No Calico CNI spec template is specified. Exiting (0)..."
    exit 0
  fi
  if [ -z "${CALICO_CNI_SPEC_TEMPLATE}" ]; then
    echo "No Calico CNI spec template is specified. Exiting (0)..."
    exit 0
  fi
  cni_spec=${CALICO_CNI_SPEC_TEMPLATE}
else
  cni_spec=${CNI_SPEC_TEMPLATE}
fi

if [ -f "/host/home/kubernetes/bin/gke" ]
then
	cni_spec=$(echo ${cni_spec:-} | sed -e "s#@cniType#gke#g")
else
	cni_spec=$(echo ${cni_spec:-} | sed -e "s#@cniType#ptp#g")
fi

# Fill CNI spec template.
token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
node_url="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/nodes/${HOSTNAME}"
ipv4_subnet=$(curl -k -s -H "Authorization: Bearer $token" $node_url | jq '.spec.podCIDR')
if [ -z "${ipv4_subnet:-}" ]; then
  echo "Failed to fetch PodCIDR from K8s API server. Exiting (1)..."
  exit 1
fi

echo "Filling IPv4 subnet ${ipv4_subnet:-}"
cni_spec=$(echo ${cni_spec:-} | sed -e "s#@ipv4Subnet#[{\"subnet\": ${ipv4_subnet:-}}]#g")

if [ "$ENABLE_PRIVATE_IPV6_ACCESS" == "true" ]; then
  node_ipv6_addr=$(curl -s -k --fail "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/?recursive=true" -H "Metadata-Flavor: Google" | jq -r '.ipv6s[0]' ) ||:

  if [ -n "${node_ipv6_addr:-}" ] && [ "${node_ipv6_addr}" != "null" ]; then
    echo "Found nic0 IPv6 address ${node_ipv6_addr:-}. Filling IPv6 subnet and route..."
    cni_spec=$(echo ${cni_spec:-} | sed -e \
      "s#@ipv6SubnetOptional#, [{\"subnet\": \"${node_ipv6_addr:-}/112\"}]#g;
       s#@ipv6RouteOptional#, {\"dst\": \"::/0\"}#g")
    
    # Ensure the IPv6 firewall rules are as expected.
    # These rules mirror the IPv4 rules installed by kubernetes/cluster/gce/gci/configure-helper.sh
    if ip6tables -w -L FORWARD | grep "Chain FORWARD (policy DROP)" > /dev/null; then
      echo "Add rules to accept all forwarded TCP/UDP/ICMP/SCTP IPv6 packets"
      ip6tables -A FORWARD -w -p tcp -j ACCEPT
      ip6tables -A FORWARD -w -p udp -j ACCEPT
      ip6tables -A FORWARD -w -p icmpv6 -j ACCEPT
      ip6tables -A FORWARD -w -p sctp -j ACCEPT
    fi

    # Ensure the other IPv6 rules we need are also installed, and in before any other node rules.
    # Always allow ICMP
    ip6tables -I INPUT -p icmpv6 -j ACCEPT -w
    ip6tables -I OUTPUT -p icmpv6 -j ACCEPT -w
    # Note that this expects dhclient to actually obtain and assign an IPv6 address to eth0.
    ip6tables -I INPUT -p udp -m udp --dport 546 -j ACCEPT
    # Accept return traffic inbound
    ip6tables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -w
    # Accept new and return traffic outbound
    ip6tables -I OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -w

    if [ "${ENABLE_CALICO_NETWORK_POLICY}" == "true" ]; then
      echo "Enabling IPv6 forwarding..."
      sysctl -w net.ipv6.conf.all.forwarding=1
    fi
  else
    echo "No IPv6 address found for nic0. Clearing IPv6 subnet and route..."
    cni_spec=$(echo ${cni_spec:-} | \
      sed -e "s#@ipv6SubnetOptional##g; s#@ipv6RouteOptional##g")
  fi
else
  echo "Clearing IPv6 subnet and route given private IPv6 access is disabled..."
  cni_spec=$(echo ${cni_spec:-} | \
    sed -e "s#@ipv6SubnetOptional##g; s#@ipv6RouteOptional##g")
fi

# Output CNI spec (template).
output_file=""
if [ "${CALICO_CNI_SPEC_TEMPLATE_FILE:-}" ]; then
  output_file=${CALICO_CNI_SPEC_TEMPLATE_FILE}
  echo "Creating Calico CNI spec template..."
else
  output_file="/host/etc/cni/net.d/${CNI_SPEC_NAME}"
  echo "Creating CNI spec..."
fi

cat >${output_file} <<EOF
${cni_spec:-}
EOF
