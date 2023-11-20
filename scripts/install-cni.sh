#!/bin/bash

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

calico_ready() {
  echo "Listing items matching /host/etc/cni/net.d/*calico*.conflist"
  echo "(this action repeats during bootstrap until a match is found)"
  # The command producing exit status must be the last command here.
  compgen -G "/host/etc/cni/net.d/*calico*.conflist"
}

cni_ready() {
  local -r cni_bin="$1"
  echo "Running '/host/home/kubernetes/bin/${cni_bin}' with CNI_COMMAND=VERSION"
  # It's necessary to try running it instead of just checking existence because
  # the CNI installer might not do atomic write (write to temporary file then move).
  echo "(errors are expected during bootstrap; will retry until success)"
  # The command producing exit status must be the last command here.
  # Send errors to stdout since they're "expected" errors.
  # This redirection doesn't affect exit status after execution.
  CNI_COMMAND=VERSION /host/home/kubernetes/bin/"${cni_bin}" 2>&1
}

# inotify callback
if [ -n "$1" ]; then
  # We run into this branch at callback from inotify. In this case, call the
  # specified function then exit. The return value from that function (exit
  # status of the last command in the function) is used as the exit status.
  # "$@" would be like "calico_ready" or "calico_ready" "cilium-cni".
  "$@"
  exit
fi

BUILD='__BUILD__'

echo "Install-CNI ($0), Build: $BUILD"

# Overide calico network policy config if its cni is not installed as expected.
# This can happen if the calico daemonset is removed but the master addon still exists.
#
# If this script is being run in order to generate the Calico config file, then skip this
# check.
echo "Calico network policy config: ${ENABLE_CALICO_NETWORK_POLICY}"
if [ "${ENABLE_CALICO_NETWORK_POLICY}" == "true" ] && [ "${WRITE_CALICO_CONFIG_FILE}" != "true" ]; then
  # inotify calls back to the beginning of this script.
  # `timeout` exits failure when it's exiting due to time out, but this is an
  # expected situation when Calico is being disabled (see below).
  timeout 120s inotify /host/etc/cni/net.d '' "$0" calico_ready \
    || echo "inotify for Calico CNI configuration files failed or timed out (status: $?)."
  # Might be possible to just use the exit status from `timeout` as the
  # condition of the if-statement below, once we have more confidence in the
  # implementations of `timeout` and `inotify`, then `set -e` can be moved to
  # the top, right after inotify callbacks.
  if ! calico_ready; then
    # This handles the disabling process: https://github.com/GoogleCloudPlatform/netd/issues/91
    ENABLE_CALICO_NETWORK_POLICY=false
    echo "Update calico network policy config to ${ENABLE_CALICO_NETWORK_POLICY}"
  fi
fi

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

if [ -f "/host/home/kubernetes/bin/gke" ]; then
  cni_spec=${cni_spec//@cniType/gke}
else
  cni_spec=${cni_spec//@cniType/ptp}
fi

if [ "${ENABLE_BANDWIDTH_PLUGIN}" == "true" ] && [ -f "/host/home/kubernetes/bin/bandwidth" ]; then
  cni_spec=${cni_spec//@cniBandwidthPlugin/, {\"type\": \"bandwidth\", \"capabilities\": {\"bandwidth\": true\}\}}
else
  cni_spec=${cni_spec//@cniBandwidthPlugin/}
fi

token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
node_url="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/nodes/${HOSTNAME}"
response=$(curl -k -s -H "Authorization: Bearer $token" "$node_url")

if [ "${MIGRATE_TO_DPV2:-}" == "true" ]; then
  DPV2_MIGRATION_READY=$(jq '.metadata.labels."cloud.google.com/gke-dpv2-migration-ready"' <<<"$response")
  echo "Migration to DPv2 in progress; node ready: '${DPV2_MIGRATION_READY}'"
  if [ "${DPV2_MIGRATION_READY}" != '"true"' ] # DPV2_MIGRATION_READY is a JSON string thus double quotes
  then
    ENABLE_CILIUM_PLUGIN=false
  fi
fi

if [ "${ENABLE_CILIUM_PLUGIN}" == "true" ]; then
  echo "Adding Cilium plug-in to the CNI config."
  cni_spec=${cni_spec//@cniCiliumPlugin/, {\"type\": \"cilium-cni\", \"enable-route-mtu\": true\}}
else
  echo "Not using Cilium plug-in."
  cni_spec=${cni_spec//@cniCiliumPlugin/}
fi

# Add istio plug-in to spec if env var is not empty
if [[ -n "${ISTIO_CNI_CONFIG:-}" ]]; then
  echo "Adding Istio plug-in to the CNI config."
  cni_spec=${cni_spec//@cniIstioPlugin/, ${ISTIO_CNI_CONFIG}}
else
  echo "Not using Istio plug-in."
  cni_spec=${cni_spec//@cniIstioPlugin/}
fi

# Fill CNI spec template.
ipv4_subnet=$(jq '.spec.podCIDR' <<<"$response")

if [[ "${ipv4_subnet:-}" =~ ^\"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/[0-9][0-9]*\"$ ]]; then
  echo "PodCIDR validation succeeded: ${ipv4_subnet:-}"
else
  echo "Response from $node_url"
  echo "$response"
  echo "Failed to fetch/validate PodCIDR from K8s API server, ipv4_subnet=${ipv4_subnet:-}. Exiting (1)..."
  exit 1
fi

echo "Filling IPv4 subnet ${ipv4_subnet:-}"
cni_spec=${cni_spec//@ipv4Subnet/[{\"subnet\": ${ipv4_subnet:-}\}]}

if [ "$ENABLE_MASQUERADE" == "true" ]; then
  echo "Config MASQUERADE rule"

  if iptables -t nat -n --list IP-MASQ >/dev/null 2>&1; then
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

STACK_TYPE=$(jq '.metadata.labels."cloud.google.com/gke-stack-type"' <<<"$response")
echo "Node stack type label: '${STACK_TYPE:-}'"

if [ "$ENABLE_IPV6" == "true" ] || [ "${STACK_TYPE:-}" == '"IPV4_IPV6"' ]; then
  node_ipv6_addr=$(curl -s -k --fail "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/?recursive=true" -H "Metadata-Flavor: Google" | jq -r '.ipv6s[0]' ) ||:

  if [ -n "${node_ipv6_addr:-}" ] && [ "${node_ipv6_addr}" != "null" ]; then
    echo "Found nic0 IPv6 address ${node_ipv6_addr:-}. Filling IPv6 subnet and route..."

    cni_spec=${cni_spec//@ipv6SubnetOptional/, [{\"subnet\": \"${node_ipv6_addr:-}/112\"\}]}
    cni_spec=${cni_spec//@ipv6RouteOptional/, ${CNI_SPEC_IPV6_ROUTE:-{\"dst\": \"::/0\"\}}}

    # Ensure the IPv6 firewall rules are as expected.
    # These rules mirror the IPv4 rules installed by kubernetes/cluster/gce/gci/configure-helper.sh

    if ip6tables -w -L INPUT | grep "Chain INPUT (policy DROP)" > /dev/null; then
      echo "Add rules to accept all inbound TCP/UDP/ICMP/SCTP IPv6 packets"
      ip6tables -A INPUT -w -p tcp -j ACCEPT
      ip6tables -A INPUT -w -p udp -j ACCEPT
      ip6tables -A INPUT -w -p icmpv6 -j ACCEPT
      ip6tables -A INPUT -w -p sctp -j ACCEPT
    fi

    if ip6tables -w -L FORWARD | grep "Chain FORWARD (policy DROP)" > /dev/null; then
      echo "Add rules to accept all forwarded TCP/UDP/ICMP/SCTP IPv6 packets"
      ip6tables -A FORWARD -w -p tcp -j ACCEPT
      ip6tables -A FORWARD -w -p udp -j ACCEPT
      ip6tables -A FORWARD -w -p icmpv6 -j ACCEPT
      ip6tables -A FORWARD -w -p sctp -j ACCEPT
    fi

    # Ensure the other IPv6 rules we need are also installed, and in before any other node rules.
    # Always allow ICMP
    ip6tables -I OUTPUT -p icmpv6 -j ACCEPT -w
    # Accept new and return traffic outbound
    ip6tables -I OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -w

    if [ "${ENABLE_CALICO_NETWORK_POLICY}" == "true" ]; then
      echo "Enabling IPv6 forwarding..."
      echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi
  else
    echo "No IPv6 address found for nic0. Clearing IPv6 subnet and route..."
    cni_spec=${cni_spec//@ipv6SubnetOptional/}
    cni_spec=${cni_spec//@ipv6RouteOptional/}
  fi
else
  echo "Clearing IPv6 subnet and route given IPv6 access is disabled..."
  cni_spec=${cni_spec//@ipv6SubnetOptional/}
  cni_spec=${cni_spec//@ipv6RouteOptional/}
fi

# MTU to use if the interface in use can't be detected.
# Will be replaced with the value of a specific interface if available.
MTU=1460
MTU_SOURCE="<default>"

# Format of `route` output:
# Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
# 0.0.0.0         192.168.0.1     0.0.0.0         UG    100    0        0 ens4
# 192.168.0.1     0.0.0.0         255.255.255.255 UH    100    0        0 ens4

# The first grep extracts the default line, and the second grep extracts the
# last field, which is the interface name. We stick to using grep to avoid
# introducing too many new dependencies.

default_nic=$(route -n | grep -E '^0\.0\.0\.0\s+\S+\s+0\.0\.0\.0' | grep -oE '\S+$')

# cilium_wg0 is the interface for node-to-node encryption. If it's available /
# in use, it has a lower MTU than the default NIC (eth0) due to encryption headers.
for nic in cilium_wg0 "$default_nic"; do
  if [ -f "/sys/class/net/$nic/mtu" ]; then
    MTU=$(cat "/sys/class/net/$nic/mtu")
    MTU_SOURCE=$nic
    break
  fi
done

# Set mtu
cni_spec=${cni_spec//@mtu/$MTU}
echo "Set the default mtu to $MTU, inherited from $MTU_SOURCE"

if [ "${ENABLE_CILIUM_PLUGIN}" == "true" ]; then
  echo "Cilium plug-in is in use. Holding CNI configurations until Cilium is ready."

  # inotify calls back to the beginning of this script.
  inotify /host/home/kubernetes/bin cilium-cni "$0" cni_ready cilium-cni
  echo "Cilium plug-in binary is now confirmed as ready."

  HEALTHZ_PORT="${CILIUM_HEALTHZ_PORT:-9879}"
  # Wait upto 60s for the cilium pod to report healthy.
  if curl -fsSm 1 --retry 60 --retry-all-errors --retry-max-time 60 --retry-delay 1 \
      -o /dev/null --stderr - \
      http://localhost:"${HEALTHZ_PORT}"/healthz; then
    echo "Cilium healthz reported success."
  else
    echo "Cilium not yet ready. Continuing anyway."
  fi
fi

# Wait for istio plug-in if it is enabled
if [[ -n "${ISTIO_CNI_CONFIG:-}" ]]; then
 echo "Istio plug-in is in use. Holding CNI configurations until Istio is ready."

 # inotify calls back to the beginning of this script.
 inotify /host/home/kubernetes/bin istio-cni "$0" cni_ready istio-cni
 echo "Istio plug-in binary is now confirmed as ready."
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

# Atomically write CNI spec
if ! temp_file=$(mktemp -- "${output_file}.tmp.XXXXXX"); then
  echo "Failed to create temp file, Exiting (1)..."
  exit 1
fi
trap 'rm -f -- "${temp_file}"' EXIT
cat <<<"${cni_spec:-}" >"${temp_file}"
mv -- "${temp_file}" "${output_file}"

# Log the CNI spec written above in log
echo "CNI spec at ${output_file}, compact: $(jq -c . -- "${output_file}")"
echo "CNI spec at ${output_file}, base64: $(base64 -w 0 -- "${output_file}")"
