/*
Copyright 2018 Google Inc.
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

package config

const (
	natTable    = "nat"
	ipMasqChain = "IP-MASQ"
)

func MasqueradeConfig() []Config {
	return []Config{
		&IPTablesChainConfig{
			TableName: natTable,
			ChainName: ipMasqChain,
		},
		&IPTablesRuleConfig{
			TableName: natTable,
			ChainName: postRoutingChain,
			RuleSpec:  []string{"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", "IP-MASQ"},
		},
		&IPTablesRuleConfig{
			TableName: natTable,
			ChainName: ipMasqChain,
			RuleSpec:  []string{"-d", "169.254.0.0/16", "-j", "RETURN"},
		},
		&IPTablesRuleConfig{
			TableName: natTable,
			ChainName: ipMasqChain,
			RuleSpec:  []string{"-d", "10.0.0.0/8", "-j", "RETURN"},
		},
		&IPTablesRuleConfig{
			TableName: natTable,
			ChainName: ipMasqChain,
			RuleSpec:  []string{"-d", "172.16.0.0/12", "-j", "RETURN"},
		},
		&IPTablesRuleConfig{
			TableName: natTable,
			ChainName: ipMasqChain,
			RuleSpec:  []string{"-d", "192.168.0.0/16", "-j", "RETURN"},
		},
		&IPTablesRuleConfig{
			TableName: natTable,
			ChainName: ipMasqChain,
			RuleSpec:  []string{"-j", "MASQUERADE"},
		},
	}
}
