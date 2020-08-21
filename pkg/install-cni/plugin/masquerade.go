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
	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
)

const (
	tableNAT             = "nat"
	ipMasqChainName      = "IP-MASQ"
	postRoutingChainName = "POSTROUTING"
)

type MasqueradeInstaller struct {
	enabled    bool
	ipv4Tables ipt.IPTabler
}

func NewMasqueradeInstaller(enabled bool, ipv4Tables ipt.IPTabler) *MasqueradeInstaller {
	return &MasqueradeInstaller{
		enabled:    enabled,
		ipv4Tables: ipv4Tables,
	}
}

func (in *MasqueradeInstaller) Run() error {
	if !in.enabled {
		return nil
	}

	glog.Info("Configure MASQUERADE rule")

	// Create IP-MASQ chain only if it does not exist yet
	if err := in.ipv4Tables.NewChain(tableNAT, ipMasqChainName); err != nil {
		if eerr, eok := err.(ipt.Error); eok && eerr.ExitStatus() == 1 {
			// ExitStatus 1 means the chain already exists
			glog.Infof("%[1]s Chain exists, skip creating %[1]s Chain and MASQ rules.", ipMasqChainName)
			return nil
		}
		return err
	}

	glog.Infof("Creating %s Chain and MASQ rules.", ipMasqChainName)
	ruleSpecs := []ipt.IPTablesSpec{
		{
			TableName: tableNAT,
			ChainName: postRoutingChainName,
			Rules: []ipt.IPTablesRule{
				{"-m", "comment", "--comment",
					"ip-masq: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ chain",
					"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", ipMasqChainName},
			},
			IPT: in.ipv4Tables,
		},
		{
			TableName: tableNAT,
			ChainName: ipMasqChainName,
			Rules: []ipt.IPTablesRule{
				{"-d", "169.254.0.0/16", "-m", "comment", "--comment", "ip-masq: local traffic is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "10.0.0.0/8", "-m", "comment", "--comment", "ip-masq: RFC 1918 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "172.16.0.0/12", "-m", "comment", "--comment", "ip-masq: RFC 1918 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "192.168.0.0/16", "-m", "comment", "--comment", "ip-masq: RFC 1918 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "240.0.0.0/4", "-m", "comment", "--comment", "ip-masq: RFC 5735 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "192.0.2.0/24", "-m", "comment", "--comment", "ip-masq: RFC 5737 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "198.51.100.0/24", "-m", "comment", "--comment", "ip-masq: RFC 5737 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "203.0.113.0/24", "-m", "comment", "--comment", "ip-masq: RFC 5737 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "100.64.0.0/10", "-m", "comment", "--comment", "ip-masq: RFC 6598 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "198.18.0.0/15", "-m", "comment", "--comment", "ip-masq: RFC 6815 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "192.0.0.0/24", "-m", "comment", "--comment", "ip-masq: RFC 6890 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-d", "192.88.99.0/24", "-m", "comment", "--comment", "ip-masq: RFC 7526 reserved range is not subject to MASQUERADE", "-j", "RETURN"},
				{"-m", "comment", "--comment", "ip-masq: outbound traffic is subject to MASQUERADE (must be last in chain)", "-j", "MASQUERADE"},
			},
			IPT: in.ipv4Tables,
		},
	}

	for _, s := range ruleSpecs {
		for _, r := range s.Rules {
			if err := s.IPT.AppendUnique(s.TableName, s.ChainName, r...); err != nil {
				return err
			}
		}
	}

	return nil
}
