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

if [ "${ENABLE_BANDWIDTH_PLUGIN}" == "true" ] && [ -f "/host/home/kubernetes/bin/bandwidth" ]
then
	cni_spec=$(echo ${cni_spec:-} | sed -e "s#@cniBandwidthPlugin#,{\"type\": \"bandwidth\",\"capabilities\": {\"bandwidth\": true}}#g")
else
	cni_spec=$(echo ${cni_spec:-} | sed -e "s#@cniBandwidthPlugin##g")
fi

# Fill CNI spec template.
token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
node_url="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/nodes/${HOSTNAME}"
response=$(curl -k -s -H "Authorization: Bearer $token" $node_url)
ipv4_subnet=$(echo $response | jq '.spec.podCIDR')

if expr "${ipv4_subnet:-}" : '"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/[0-9][0-9]*"' >/dev/null; then
  echo "PodCIDR validation succeeded: ${ipv4_subnet:-}"
else
  echo "Response from $node_url"
  echo "$response"
  echo "Failed to fetch/validate PodCIDR from K8s API server, ipv4_subnet=${ipv4_subnet:-}. Exiting (1)..."
  exit 1
fi

echo "Filling IPv4 subnet ${ipv4_subnet:-}"
cni_spec=$(echo ${cni_spec:-} | sed -e "s#@ipv4Subnet#[{\"subnet\": ${ipv4_subnet:-}}]#g")

if [ "$ENABLE_MASQUERADE" == "true" ]; then
  echo "Config MASQUERADE rule"

  rule_exist=0
  iptables -t nat -n --list IP-MASQ >/dev/null 2>&1 || rule_exist=$? 
  if [ $rule_exist -eq 0 ]
  then
    echo "IP-MASQ Chain exists, skip creating IP-MASQ Chain and MASQ rules."
  else
    echo "Creating IP-MASQ Chain and MASQ rules."
    iptables -w -t nat -N IP-MASQ
    iptables -w -t nat -A POSTROUTING -m comment --comment "ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ
    iptables -w -t nat -A IP-MASQ -d 169.254.0.0/16 -m comment --comment "ip-masq: local traffic is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 10.0.0.0/8 -m comment --comment "ip-masq: RFC 1918 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 172.16.0.0/12 -m comment --comment "ip-masq: RFC 1918 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 192.168.0.0/16 -m comment --comment "ip-masq: RFC 1918 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 240.0.0.0/4 -m comment --comment "ip-masq: RFC 5735 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 192.0.2.0/24 -m comment --comment "ip-masq: RFC 5737 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 198.51.100.0/24 -m comment --comment "ip-masq: RFC 5737 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 203.0.113.0/24 -m comment --comment "ip-masq: RFC 5737 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 100.64.0.0/10 -m comment --comment "ip-masq: RFC 6598 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 198.18.0.0/15 -m comment --comment "ip-masq: RFC 6815 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 192.0.0.0/24 -m comment --comment "ip-masq: RFC 6890 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -d 192.88.99.0/24 -m comment --comment "ip-masq: RFC 7526 reserved range is not subject to MASQUERADE" -j RETURN
    iptables -w -t nat -A IP-MASQ -m comment --comment "ip-masq: outbound traffic is subject to MASQUERADE (must be last in chain)" -j MASQUERADE
  fi
fi

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

# Set mtu
default_nic=$(ip route get 8.8.8.8 | sed -nr "s/.*dev ([^\ ]+).*/\1/p")
if [ -f "/sys/class/net/$default_nic/mtu" ]; then
  MTU=$(cat /sys/class/net/$default_nic/mtu)
  cni_spec=$(echo ${cni_spec:-} | sed -e "s#@mtu#$MTU#g")
  echo "Set the default mtu to $MTU, inherited from dev $default_nic"
else
  cni_spec=$(echo ${cni_spec:-} | sed -e "s#@mtu#1460#g")
  echo "Failed to read mtu from dev $default_nic, set the default mtu to 1460"
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
