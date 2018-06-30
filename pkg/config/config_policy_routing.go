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

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	sysctlReversePathFilter = "net.ipv4.conf.all.rp_filter"
	sysctlSrcValidMark      = "net.ipv4.conf.all.src_valid_mark"
)

const (
	tableMangle         = "mangle"
	preRoutingChain     = "PREROUTING"
	postRoutingChain    = "POSTROUTING"
	gcpPreRoutingChain  = "GCP-PREROUTING"
	gcpPostRoutingChain = "GCP-POSTROUTING"
	hairpinMark         = 0x4000
	hairpinMask         = 0x4000
)

const (
	customRouteTable = 1
	maxRulePriority  = 30000
)

var (
	defaultGateway   net.IP
	defaultLinkIndex int
	localLinkIndex   int
	defaultNetDev    string
	localNetDev      string
)

func init() {
	routes, err := netlink.RouteGet(net.IPv4(8, 8, 8, 8))
	if err != nil {
		return
	}

	for _, r := range routes {
		if r.Dst == nil {
			defaultLinkIndex = r.LinkIndex
			defaultGateway = r.Gw
			l, err := netlink.LinkByIndex(defaultLinkIndex)
			if err != nil {
				return
			}
			defaultNetDev = l.Attrs().Name
		}
		if r.Src.IsLoopback() {
			localLinkIndex = r.LinkIndex
			l, err := netlink.LinkByIndex(localLinkIndex)
			if err != nil {
				return
			}
			localNetDev = l.Attrs().Name
		}
	}
}

func PolicyRoutingConfig() []Config {
	return []Config{
		SysctlConfig{
			Key:   sysctlReversePathFilter,
			Value: "2",
		},
		SysctlConfig{
			Key:   sysctlSrcValidMark,
			Value: "1",
		},
		IPTablesChainConfig{
			TableName: tableMangle,
			ChainName: gcpPreRoutingChain,
		},
		IPTablesRuleConfig{
			TableName: tableMangle,
			ChainName: preRoutingChain,
			RuleSpec:  []string{"-j", gcpPreRoutingChain},
		},
		IPTablesRuleConfig{
			TableName: tableMangle,
			ChainName: gcpPreRoutingChain,
			RuleSpec:  []string{"-j", "CONNMARK", "--restore-mark"},
		},
		IPTablesChainConfig{
			TableName: tableMangle,
			ChainName: gcpPostRoutingChain,
		},
		IPTablesRuleConfig{
			TableName: tableMangle,
			ChainName: postRoutingChain,
			RuleSpec:  []string{"-j", gcpPostRoutingChain},
		},
		IPTablesRuleConfig{
			TableName: tableMangle,
			ChainName: gcpPostRoutingChain,
			RuleSpec:  []string{"-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", hairpinMark, hairpinMask), "-j", "CONNMARK", "--save-mark"},
		},
		IPRouteConfig{
			Route: netlink.Route{
				Table:     customRouteTable,
				LinkIndex: defaultLinkIndex,
				Gw:        defaultGateway,
				Dst:       nil,
			},
		},
		IPRuleConfig{
			Rule: netlink.Rule{
				IifName:  defaultNetDev,
				Invert:   true,
				Table:    customRouteTable,
				Priority: maxRulePriority,
			},
		},
		IPRuleConfig{
			Rule: netlink.Rule{
				IifName:  localNetDev,
				Table:    unix.RT_TABLE_MAIN,
				Priority: maxRulePriority - 1,
			},
		},
		IPRuleConfig{
			Rule: netlink.Rule{
				Mark:     hairpinMark,
				Mask:     hairpinMask,
				Table:    unix.RT_TABLE_MAIN,
				Priority: maxRulePriority - 2,
			},
		},
	}
}
