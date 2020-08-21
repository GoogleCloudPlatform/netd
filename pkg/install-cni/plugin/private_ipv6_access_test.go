/*
Copyright 2020 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GoogleCloudPlatform/netd/internal/ipt/ipttest"
	"github.com/GoogleCloudPlatform/netd/internal/rest/resttest"
	"github.com/GoogleCloudPlatform/netd/internal/systemutil/sysctltest"
)

const (
	cniTemplateIPv6 = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
     {
  	  "type": "ptp",
  	  "mtu": 1460,
  	  "ipam": {
  		"type": "host-local",
  		"ranges": [
          [
            {
              "subnet": "10.0.0.0/24"
            }
          ]@ipv6SubnetOptional
  		],
  		"routes": [
  		  {
            "dst": "0.0.0.0/0"
          }@ipv6RouteOptional
  		]
  	  }
  	}
  ]
}
`
	cniTemplateIPv6Golden = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
     {
  	  "type": "ptp",
  	  "mtu": 1460,
  	  "ipam": {
  		"type": "host-local",
  		"ranges": [
          [
            {
              "subnet": "10.0.0.0/24"
            }
          ],
          [
            {
              "subnet": "IPV6_ADDR/112"
            }
          ]
  		],
  		"routes": [
  		  {
            "dst": "0.0.0.0/0"
          },
          {
            "dst": "::/0"
          }
  		]
  	  }
  	}
  ]
}
`
	cniTemplateIPv6NoKeys = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
     {
  	  "type": "ptp",
  	  "mtu": 1460,
  	  "ipam": {
  		"type": "host-local",
  		"ranges": [
          [
            {
              "subnet": "10.0.0.0/24"
            }
          ]
  		],
  		"routes": [
  		  {
            "dst": "0.0.0.0/0"
          }
  		]
  	  }
  	}
  ]
}
`
	cniConfigNoIPv6Golden = cniTemplateIPv6NoKeys
)

const (
	resBodyIPv6Addr   = `{"ip":"10.128.15.213","ipAliases":["10.0.1.0/24"],"ipv6s":["IPV6_ADDR"],"mac":"42:01:0a:80:0f:d5","mtu":1460}`
	resBodyNoIPv6Addr = `{"ip":"10.128.15.213","ipAliases":["10.0.1.0/24"],"mac":"42:01:0a:80:0f:d5","mtu":1460}`
)

func TestPrivateIPv6AccessInstaller(t *testing.T) {
	forwardChainRules := []string{
		"-p tcp -j ACCEPT",
		"-p udp -j ACCEPT",
		"-p icmpv6 -j ACCEPT",
		"-p sctp -j ACCEPT",
	}
	// New rules are inserted to INPUT and OUTPUT chains
	// Expect correct ordering
	inputChainRules := []string{
		"-m state --state ESTABLISHED,RELATED -j ACCEPT",
		"-p udp -m udp --dport 546 -j ACCEPT",
		"-p icmpv6 -j ACCEPT",
		"existing rule",
	}
	outputChainRules := []string{
		"-m state --state NEW,ESTABLISHED,RELATED -j ACCEPT",
		"-p icmpv6 -j ACCEPT",
		"existing rule",
	}

	cases := []struct {
		name                      string
		enabled                   bool
		nodeIPv6Enabled           bool
		forwardChainDrop          bool
		enableCalicoNetworkPolicy bool
		cniConfigTemplate         string
		expectedCNIConfig         string
	}{
		{
			name:              "not enabled",
			enabled:           false,
			cniConfigTemplate: cniTemplateIPv6,
			expectedCNIConfig: cniConfigNoIPv6Golden,
		},
		{
			name:              "enabled/node IPv6 disabled",
			enabled:           true,
			nodeIPv6Enabled:   false,
			cniConfigTemplate: cniTemplateIPv6,
			expectedCNIConfig: cniConfigNoIPv6Golden,
		},
		{
			name:                      "enabled/FORWARD chain ACCEPT calico network policy disabled",
			enabled:                   true,
			nodeIPv6Enabled:           true,
			forwardChainDrop:          false,
			enableCalicoNetworkPolicy: false,
			cniConfigTemplate:         cniTemplateIPv6,
			expectedCNIConfig:         cniTemplateIPv6Golden,
		},
		{
			name:                      "enabled/FORWARD chain DROP calico network policy disabled",
			enabled:                   true,
			nodeIPv6Enabled:           true,
			forwardChainDrop:          true,
			enableCalicoNetworkPolicy: false,
			cniConfigTemplate:         cniTemplateIPv6,
			expectedCNIConfig:         cniTemplateIPv6Golden,
		},
		{
			name:                      "enabled/FORWARD chain ACCEPT calico network policy enabled",
			enabled:                   true,
			nodeIPv6Enabled:           true,
			forwardChainDrop:          false,
			enableCalicoNetworkPolicy: true,
			cniConfigTemplate:         cniTemplateIPv6,
			expectedCNIConfig:         cniTemplateIPv6Golden,
		},
		{
			name:                      "enabled/FORWARD chain DROP calico network policy enabled",
			enabled:                   true,
			nodeIPv6Enabled:           true,
			forwardChainDrop:          true,
			enableCalicoNetworkPolicy: true,
			cniConfigTemplate:         cniTemplateIPv6,
			expectedCNIConfig:         cniTemplateIPv6Golden,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ipv6ForwardingVal := "default value"
			fakeSysctl := sysctltest.FakeSysctl{sysctlIPv6Forwarding: ipv6ForwardingVal}

			var resBody string
			var mockClient *resttest.MockClient
			if c.nodeIPv6Enabled {
				resBody = resBodyIPv6Addr
			} else {
				resBody = resBodyNoIPv6Addr
			}
			mockClient = resttest.NewMockClient(func(*http.Request) (*http.Response, error) {
				r := ioutil.NopCloser(bytes.NewReader([]byte(resBody)))
				return &http.Response{
					StatusCode: 200,
					Body:       r,
				}, nil
			})

			// Initialize system default iptables chains
			expectedIPT := ipttest.NewFakeIPTables(tableFilter)
			expectedIPT.NewChain(tableFilter, forwardChainName)
			expectedIPT.NewChain(tableFilter, inputChainName)
			expectedIPT.NewChain(tableFilter, outputChainName)

			actualIPT := ipttest.NewFakeIPTables(tableFilter)
			actualIPT.NewChain(tableFilter, forwardChainName)
			actualIPT.NewChain(tableFilter, inputChainName)
			actualIPT.NewChain(tableFilter, outputChainName)

			if c.enabled {
				if c.forwardChainDrop {
					expectedIPT.Tables[tableFilter].Policies[forwardChainName] = ipttest.DropPolicy
					actualIPT.Tables[tableFilter].Policies[forwardChainName] = ipttest.DropPolicy
					// Expect installer to create the FORWARD rules
					expectedIPT.Tables[tableFilter].Rules[forwardChainName] = forwardChainRules
				}

				if c.nodeIPv6Enabled {
					// Create existing rule to test if new rules were inserted at the head of the INPUT and OUTPUT chains
					actualIPT.AppendUnique(tableFilter, inputChainName, "existing", "rule")
					actualIPT.AppendUnique(tableFilter, outputChainName, "existing", "rule")

					// Expect installer to create the INPUT and OUTPUT rules with correct ordering
					expectedIPT.Tables[tableFilter].Rules[inputChainName] = inputChainRules
					expectedIPT.Tables[tableFilter].Rules[outputChainName] = outputChainRules
				}
			}

			in := NewPrivateIPv6AccessInstaller(c.enabled, c.enableCalicoNetworkPolicy, fakeSysctl.Sysctl, mockClient, actualIPT, &c.cniConfigTemplate)
			assert.NoError(t, in.Run())

			if c.enableCalicoNetworkPolicy {
				ipv6ForwardingVal = "1"
			}
			val, err := fakeSysctl.Sysctl(sysctlIPv6Forwarding)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, val, ipv6ForwardingVal)

			assert.Equal(t, actualIPT, expectedIPT)
			assert.Equal(t, c.expectedCNIConfig, c.cniConfigTemplate)
			checkJSONFormat(t, c.cniConfigTemplate)
		})
	}

}
