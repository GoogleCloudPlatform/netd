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
if ["${ENABLE_CALICO_NETWORK_POLICY}" = true]; then
  echo "Calico Network Policy is enabled by ENABLE_CALICO_NETWORK_POLICY. Disabling CNI Spec generation."
  exit 0
fi
  

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
