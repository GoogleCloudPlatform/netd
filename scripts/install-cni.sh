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

# shellcheck disable=SC2317 # when called with $1=cni_ready
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
if [[ -n "$1" ]]; then
  # We run into this branch at callback from inotify. In this case, call the
  # specified function then exit. The return value from that function (exit
  # status of the last command in the function) is used as the exit status.
  # "$@" would be like "calico_ready" or "cni_ready" "cilium-cni".
  "$@"
  exit
fi

BUILD='__BUILD__'

echo "Install-CNI ($0), Build: $BUILD"

set -u -e

# Overide calico network policy config if its cni is not installed as expected.
# This can happen if the calico daemonset is removed but the master addon still exists.
#
# If this script is being run in order to generate the Calico config file, then skip this
# check.
echo "Calico network policy enabled: '${ENABLE_CALICO_NETWORK_POLICY:-}'; write config: '${WRITE_CALICO_CONFIG_FILE:-}'"
if [[ "${ENABLE_CALICO_NETWORK_POLICY:-}" == "true" && "${WRITE_CALICO_CONFIG_FILE:-}" != "true" ]]; then
  # inotify calls back to the beginning of this script.
  # `timeout` exits failure when it's exiting due to time out, but this is an
  # expected situation when Calico is being disabled (see below).
  timeout 120s inotify /host/etc/cni/net.d '' "$0" calico_ready \
    || echo "inotify for Calico CNI configuration files failed or timed out (status: $?)."
  # Might be possible to just use the exit status from `timeout` as the
  # condition of the if-statement below, once we have more confidence in the
  # implementations of `timeout` and `inotify`, then `set -e` can be moved to
  # the top, right after inotify callbacks.
  if calico_ready; then
    echo "Calico has written CNI config files. No action needed here."
    exit 0
  else
    # This handles the disabling process: https://github.com/GoogleCloudPlatform/netd/issues/91
    ENABLE_CALICO_NETWORK_POLICY=false
    echo "Update calico network policy config to ${ENABLE_CALICO_NETWORK_POLICY}"
  fi
fi

cni_spec=${CALICO_CNI_SPEC_TEMPLATE:-${CNI_SPEC_TEMPLATE:-}}
if [[ -z "${cni_spec}" ]]; then
  echo "No CNI spec template or empty template is specified. Not taking actions."
  exit 0
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

if [[ "${ENABLE_CILIUM_PLUGIN}" == "true" ]]; then
  cilium_cni_config='{"type": "cilium-cni", "enable-route-mtu": true}'
  if [[ -n "${CILIUM_FAST_START_NAMESPACES:-}" ]]; then
    cilium_cni_config=$(jq --arg namespaces "${CILIUM_FAST_START_NAMESPACES:-}" '.["dpv2-fast-start-namespaces"] = $namespaces' <<<"${cilium_cni_config}")
  fi
  echo "Adding Cilium plug-in to the CNI config: '$(jq -c . <<<"${cilium_cni_config}")'"
  cni_spec=${cni_spec//@cniCiliumPlugin/, ${cilium_cni_config}}
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

# ip6tables need to be propagated only if IPv6 is in use in directpath, dual-stack or IPv6 clusters.
# this flag is raised if at any point IPv6 subnet is configured.
POPULATE_IP6TABLES="false"

# Fill CNI spec template.
#######################################
# Checks if given subnet is valid IPv4 range.
# Arguments:
#   Subnet
# Returns:
#   0 if valid, 1 on invalid.
#######################################
function is_ipv4_range {
  local IPV4_RANGE_REGEXP='^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$'
  local ip=$1

  [[ "${ip:-}" =~ ${IPV4_RANGE_REGEXP} ]]
}

#######################################
# Checks if given subnet is valid IPv6 range.
# Arguments:
#   Subnet
# Returns:
#   0 if valid, 1 on invalid.
#######################################
function is_ipv6_range {
  local IPV6_RANGE_REGEXP='^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/[0-9]{1,3}$'
  local ip=$1

  [[ "${ip:-}" =~ ${IPV6_RANGE_REGEXP} ]]
}

#######################################
# Replaces `@subnets` and `@routes` placeholders using `.spec.podCIDRs` from node json.
# In directpath use case it additionally adds IPv6 subnet derived from node's IPv6 address.
# Arguments:
#   node json from kube-apiserver
#   node_ipv6_addr node's IPv6 address from GCE metadata server
#######################################
function fillSubnetsInCniSpecV2Template {
  local node=$1
  local node_ipv6_addr=$2

  local SUBNETS_REPLACEMENT=()
  local ROUTES_REPLACEMENT=()

  local ipv6_subnet_configured="false"

  for subnet in $(jq -r '.spec.podCIDRs[]' <<<"$node") ; do
    if is_ipv4_range "${subnet}" ; then
      echo "IPv4 subnet detected in .spec.podCIDRs: '${subnet:-}'"
      if [ "${ENABLE_CALICO_NETWORK_POLICY}" == "true" ]; then
        # calico uses special value `usePodCidr` instead of directly providing IP range
        SUBNETS_REPLACEMENT+=('[{"subnet": "usePodCidr"}]')
        ROUTES_REPLACEMENT+=('{"dst": "0.0.0.0/0"}')
      else
        SUBNETS_REPLACEMENT+=("$(jq -nc --arg subnet "${subnet}" '[{"subnet": $subnet}]')")
        ROUTES_REPLACEMENT+=('{"dst": "0.0.0.0/0"}')
      fi
    elif is_ipv6_range "${subnet}" ; then
      echo "IPv6 subnet detected in .spec.podCIDRs: '${subnet:-}'"
      POPULATE_IP6TABLES="true"
      echo "ip6tables will be populated because IPv6 podCIDR is configured (from .spec.podCIDRs)"
      ipv6_subnet_configured="true"
      SUBNETS_REPLACEMENT+=("$(jq -nc --arg subnet "${subnet}" '[{"subnet": $subnet}]')")
      ROUTES_REPLACEMENT+=('{"dst": "::/0"}')
    else
      echo "[ERROR] Subnet detected in .spec.podCIDRs '${subnet}' is not a valid IP range"
      exit 1
    fi
  done

  # Directpath use case
  if [ "$ipv6_subnet_configured" == "false" ] ; then
    # Directpath adds IPv6 subnet and route derived from host with fixed range
    # of /112 even when it is not specified in node's .spec.podCIDRs
    if [ -n "${node_ipv6_addr:-}" ] && [ "${node_ipv6_addr}" != "null" ]; then
      POPULATE_IP6TABLES="true"
      echo "ip6tables will be populated because IPv6 podCIDR is configured (for directpath)"
      local subnet_from_node_ipv6_addr="${node_ipv6_addr}/112"
      SUBNETS_REPLACEMENT+=("$(jq -nc --arg subnet "${subnet_from_node_ipv6_addr}" '[{"subnet": $subnet}]')")
      ROUTES_REPLACEMENT+=("${CNI_SPEC_IPV6_ROUTE:-{\"dst\": \"::/0\"\}}")
    fi
  fi

  SUBNETS_REPLACEMENT_CONCATENATED=$(IFS=', ' ; echo "${SUBNETS_REPLACEMENT[*]}")
  ROUTES_REPLACEMENT_CONCATENATED=$(IFS=', ' ; echo "${ROUTES_REPLACEMENT[*]}")

  cni_spec=${cni_spec//@subnets/$SUBNETS_REPLACEMENT_CONCATENATED}
  cni_spec=${cni_spec//@routes/$ROUTES_REPLACEMENT_CONCATENATED}
}

#######################################
# Replaces `@ipv4Subnet', '@ipv6SubnetOptional` and `@ipv6RouteOptional` placeholders using `.spec.podCIDR` from node json and node's ipv6 from metadata server.
# Arguments:
#   node json from kube-apiserver
#   node_ipv6_addr node's IPv6 address from GCE metadata server
#######################################
function fillSubnetsInCniSpecLegacyTemplate {
  local node=$1
  local node_ipv6_addr=$2

  local primary_subnet
  primary_subnet=$(jq -r '.spec.podCIDR' <<<"$node")

  if is_ipv4_range "${primary_subnet:-}" ; then
    echo "PodCIDR IPv4 detected: '${primary_subnet:-}'"
    cni_spec=${cni_spec//@ipv4Subnet/[{\"subnet\": \"${primary_subnet:-}\"\}]}
  elif is_ipv6_range "${primary_subnet:-}" ; then
    echo "Primary IPv6 pod range detected '${primary_subnet:-}'. It will only work with new spec template."
    exit 1
  else
    echo "Response from $node_url"
    echo "$node"
    echo "Failed to fetch PodCIDR from K8s API server, primary_subnet=${primary_subnet:-}. Exiting (1)..."
    exit 1
  fi

  if [ -n "${node_ipv6_addr:-}" ] && [ "${node_ipv6_addr}" != "null" ]; then
    echo "Found nic0 IPv6 address ${node_ipv6_addr:-}. Filling IPv6 subnet and route..."
    POPULATE_IP6TABLES="true"
    echo "ip6tables will be populated because IPv6 podCIDR is configured (from node interface)"

    cni_spec=${cni_spec//@ipv6SubnetOptional/, [{\"subnet\": \"${node_ipv6_addr:-}/112\"\}]}
    cni_spec=${cni_spec//@ipv6RouteOptional/, ${CNI_SPEC_IPV6_ROUTE:-{\"dst\": \"::/0\"\}}}
  else
    echo "No IPv6 address found for nic0. Clearing IPv6 subnet and route..."
    cni_spec=${cni_spec//@ipv6SubnetOptional/}
    cni_spec=${cni_spec//@ipv6RouteOptional/}
  fi
}

function fillSubnetsInCniSpec {
  case "${CNI_SPEC_TEMPLATE_VERSION:-}" in
    2*)
      fillSubnetsInCniSpecV2Template "$1" "$2"
      ;;
    *)
      fillSubnetsInCniSpecLegacyTemplate "$1" "$2"
  esac
}


CLUSTER_STACK_TYPE=$(jq -r '.metadata.labels."cloud.google.com/gke-stack-type"' <<<"$response")
echo "Node's cluster stack type label: '${CLUSTER_STACK_TYPE:-}'"

node_ipv6_addr=''
if [ "$ENABLE_IPV6" == "true" ] || [ "${CLUSTER_STACK_TYPE:-}" == "IPV4_IPV6" ]; then
  node_ipv6_addr=$(curl -s -k --fail "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/?recursive=true" -H "Metadata-Flavor: Google" | jq -r '.ipv6s[0]' ) ||:
fi

fillSubnetsInCniSpec "$response" "$node_ipv6_addr"

if [ "$POPULATE_IP6TABLES" == "true" ] ; then
  # Ensure the IPv6 firewall rules are as expected.
  # These rules mirror the IPv4 rules installed by kubernetes/cluster/gce/gci/configure-helper.sh
  echo "Ensuring IPv6 firewall rules with ip6tables"

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
    echo 1 > "${IPV6_FORWARDING_CONF:-/proc/sys/net/ipv6/conf/all/forwarding}"
  fi
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
fi

# Wait for istio plug-in if it is enabled
if [[ -n "${ISTIO_CNI_CONFIG:-}" ]]; then
 echo "Istio plug-in is in use. Holding CNI configurations until Istio is ready."

 # inotify calls back to the beginning of this script.
 inotify /host/home/kubernetes/bin istio-cni "$0" cni_ready istio-cni
 echo "Istio plug-in binary is now confirmed as ready."
fi

# Atomically write to file.
function write_file {
  local file=$1
  local content=$2

  local temp_file
  # Potential failure from mktemp will be caught by global `set -e`.
  temp_file=$(mktemp -- "${file}.tmp.XXXXXX")
  trap 'rm -f -- "${temp_file}"' EXIT

  cat <<<"${content}" >"${temp_file}"
  mv -- "${temp_file}" "${file}"
  rm -f -- "${temp_file}"
  trap - EXIT

  echo "File written to '${file}' with content (base64): $(base64 -w 0 -- "${file}")"
}

# Output CNI spec (template).
output_file=${CALICO_CNI_SPEC_TEMPLATE_FILE:-/host/etc/cni/net.d/${CNI_SPEC_NAME}}

# Wait up to the specified time for the cilium pod to report healthy.
cilium_health_check() {
  local retry_max_time=$1
  local healthz_port=${2:-${CILIUM_HEALTHZ_PORT:-9879}}

  curl -fsSm 1 --retry "${retry_max_time}" --retry-all-errors \
    --retry-max-time "${retry_max_time}" --retry-delay 1 \
    -o /dev/null --stderr - \
    http://localhost:"${healthz_port}"/healthz
}

# Try to decouple RUN_CNI_WATCHDOG and ENABLE_CILIUM_PLUGIN; don't assume
# ENABLE_CILIUM_PLUGIN is set whenever RUN_CNI_WATCHDOG is set.
if [[ "${RUN_CNI_WATCHDOG:-}" != "true" ]]; then

  # In non-watchdog mode, we must exit after writing CNI config.
  echo "Not running CNI watchdog. Will exit as soon as CNI config is written."

  if [[ "${ENABLE_CILIUM_PLUGIN:-}" == "true" ]]; then
    if cilium_health_check "${CILIUM_HEALTH_MAX_WAIT_TIME:-600}"; then
      echo "Cilium healthz reported success."
    else
      echo "Cilium not yet ready. Continuing anyway."
    fi
  fi

  echo "Creating CNI spec at '${output_file}' with content: $(jq -c . <<<"${cni_spec}")"
  write_file "${output_file}" "${cni_spec}"

  exit 0
fi

# In watchdog mode, we should write CNI config but never exit.
if [[ "${ENABLE_CILIUM_PLUGIN:-}" != "true" ]]; then
  echo "Running CNI watchdog, but there is no Cilium to watch."

  echo "Creating CNI spec at '${output_file}' with content: $(jq -c . <<<"${cni_spec}")"
  write_file "${output_file}" "${cni_spec}"

  while true; do
    echo "Sleeping infinity now."
    sleep infinity
  done
  # In case of anything unexpected, don't fallthrough to the logic below.
  exit 1
fi

echo "Running CNI watchdog to watch Cilium and manage CNI config at '${output_file}' with content: $(jq -c . <<<"${cni_spec}")"
cilium_watchdog_success_wait=${CILIUM_WATCHDOG_SUCCESS_WAIT:-300}
cilium_watchdog_failure_retry=${CILIUM_WATCHDOG_FAILURE_RETRY:-60}
cilium_watchdog_fast_start_wait=${CILIUM_WATCHDOG_FAST_START_WAIT:-60}

if [[ -n "${CILIUM_FAST_START_NAMESPACES:-}" ]]; then
  echo "Cilium has fast-start; writing CNI config upfront then wait for ${cilium_watchdog_fast_start_wait}s and start to check Cilium health."
  write_file "${output_file}" "${cni_spec}"
  sleep "${cilium_watchdog_fast_start_wait}"s
fi

while true; do
  echo "Checking Cilium health allowing retries for up to ${cilium_watchdog_failure_retry}s."
  if cilium_health_check "${cilium_watchdog_failure_retry}"; then
    echo "Cilium healthz reported success; writing CNI config if not already there then wait for ${cilium_watchdog_success_wait}s."
    [[ ! -f "${output_file}" ]] && write_file "${output_file}" "${cni_spec}"
    sleep "${cilium_watchdog_success_wait}"s
  else
    echo "Cilium does not appear healthy; removing CNI config if it exists."
    rm -f -- "${output_file}"
  fi
done

# In case of anything unexpected, signal failure.
exit 1
