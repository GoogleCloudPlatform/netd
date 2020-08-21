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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GoogleCloudPlatform/netd/internal/ipt/ipttest"
)

func TestMasqueradeInstaller(t *testing.T) {
	postRoutingChainRules := []string{
		"-m comment --comment ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain" +
			" -m addrtype ! --dst-type LOCAL -j IP-MASQ",
	}
	ipMasqChainRules := []string{
		"-d 169.254.0.0/16 -m comment --comment ip-masq: local traffic is not subject to MASQUERADE -j RETURN",
		"-d 10.0.0.0/8 -m comment --comment ip-masq: RFC 1918 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 172.16.0.0/12 -m comment --comment ip-masq: RFC 1918 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 192.168.0.0/16 -m comment --comment ip-masq: RFC 1918 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 240.0.0.0/4 -m comment --comment ip-masq: RFC 5735 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 192.0.2.0/24 -m comment --comment ip-masq: RFC 5737 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 198.51.100.0/24 -m comment --comment ip-masq: RFC 5737 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 203.0.113.0/24 -m comment --comment ip-masq: RFC 5737 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 100.64.0.0/10 -m comment --comment ip-masq: RFC 6598 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 198.18.0.0/15 -m comment --comment ip-masq: RFC 6815 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 192.0.0.0/24 -m comment --comment ip-masq: RFC 6890 reserved range is not subject to MASQUERADE -j RETURN",
		"-d 192.88.99.0/24 -m comment --comment ip-masq: RFC 7526 reserved range is not subject to MASQUERADE -j RETURN",
		"-m comment --comment ip-masq: outbound traffic is subject to MASQUERADE (must be last in chain) -j MASQUERADE",
	}

	cases := []struct {
		name              string
		enabled           bool
		ipMasqChainExists bool
	}{
		{
			name:    "not enabled",
			enabled: false,
		},
		{
			name:              "enabled IP-MASQ chain exists already",
			enabled:           true,
			ipMasqChainExists: true,
		},
		{
			name:              "enabled IP-MASQ chain does not exist already",
			enabled:           true,
			ipMasqChainExists: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expectedIPT := ipttest.NewFakeIPTables(tableNAT)
			expectedIPT.NewChain(tableNAT, postRoutingChainName)

			actualIPT := ipttest.NewFakeIPTables(tableNAT)
			actualIPT.NewChain(tableNAT, postRoutingChainName)

			if c.enabled {
				// If masquerade is enabled, we expect an IP-MASQ chain to exist after running installer
				expectedIPT.NewChain(tableNAT, ipMasqChainName)
				if c.ipMasqChainExists {
					// IP-MASQ chain already exists, rules should not change
					actualIPT.NewChain(tableNAT, ipMasqChainName)
				} else {
					// Expect installer to create these MASQ rules
					expectedIPT.Tables[tableNAT].Rules[postRoutingChainName] = postRoutingChainRules
					expectedIPT.Tables[tableNAT].Rules[ipMasqChainName] = ipMasqChainRules
				}
			}

			in := NewMasqueradeInstaller(c.enabled, actualIPT)

			assert.NoError(t, in.Run())
			assert.Equal(t, actualIPT, expectedIPT)
		})
	}

}
