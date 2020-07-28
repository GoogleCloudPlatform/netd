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

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	sysctlSrcValidMark = "net.ipv4.conf.all.src_valid_mark"
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
	policyRoutingGcpPreRoutingComment  = "restore the conn mark if applicable"
	policyRoutingPreRoutingComment     = "redirect all traffic to GCP-PREROUTING chain"
	policyRoutingGcpPostRoutingComment = "save the conn mark only if hairpin bit (0x4000/0x4000) is set"
	policyRoutingPostRoutingComment    = "redirect all traffic to GCP-POSTROUTING chain"
)

const (
	customRouteTable    = 1
	hairpinRulePriority = 30000 + iota
	localRulePriority
	policyRoutingRulePriority
)

var (
	defaultGateway   net.IP
	defaultLinkIndex int
	defaultNetdev    string
	localLinkIndex   int
	localNetdev      string
)

// PolicyRoutingConfigSet defines the Policy Routing rules
var PolicyRoutingConfigSet = Set{
	false,
	"PolicyRouting",
	nil,
}

func init() {
	f := func(ip net.IP) (linkIndex int, netdev string, gw net.IP) {
		routes, err := netlink.RouteGet(ip)
		if err != nil {
			glog.Errorf("failed to get route for IP: %v (%v)", ip, err)
			return
		}
		gw = routes[0].Gw
		linkIndex = routes[0].LinkIndex

		l, err := netlink.LinkByIndex(linkIndex)
		if err != nil {
			glog.Errorf("failed to get the link by index: %v (%v)", linkIndex, err)
		}
		netdev = l.Attrs().Name
		return
	}
	defaultLinkIndex, defaultNetdev, defaultGateway = f(net.IPv4(8, 8, 8, 8))
	localLinkIndex, localNetdev, _ = f(net.IPv4(127, 0, 0, 1))

	sysctlReversePathFilter := fmt.Sprintf("net.ipv4.conf.%s.rp_filter", defaultNetdev)
	PolicyRoutingConfigSet.Configs = []Config{
		SysctlConfig{
			Key:          sysctlReversePathFilter,
			Value:        "2",
			DefaultValue: "1",
			SysctlFunc:   sysctl.Sysctl,
		},
		SysctlConfig{
			Key:          sysctlSrcValidMark,
			Value:        "1",
			DefaultValue: "0",
			SysctlFunc:   sysctl.Sysctl,
		},
		IPTablesRuleConfig{
			IPTablesChainSpec{
				TableName:      tableMangle,
				ChainName:      gcpPreRoutingChain,
				IsDefaultChain: false,
				IPT:            ipt,
			},
			[]IPTablesRuleSpec{
				[]string{"-j", "CONNMARK", "--restore-mark", "-m", "comment", "--comment", policyRoutingGcpPreRoutingComment},
			},
			ipt,
		},
		IPTablesRuleConfig{
			IPTablesChainSpec{
				TableName:      tableMangle,
				ChainName:      preRoutingChain,
				IsDefaultChain: true,
				IPT:            ipt,
			},
			[]IPTablesRuleSpec{
				[]string{"-j", gcpPreRoutingChain, "-m", "comment", "--comment", policyRoutingPreRoutingComment},
			},
			ipt,
		},
		IPTablesRuleConfig{
			IPTablesChainSpec{
				TableName:      tableMangle,
				ChainName:      gcpPostRoutingChain,
				IsDefaultChain: false,
				IPT:            ipt,
			},
			[]IPTablesRuleSpec{
				[]string{"-m", "mark", "--mark",
					fmt.Sprintf("0x%x/0x%x", hairpinMark, hairpinMask),
					"-j", "CONNMARK", "--save-mark", "-m", "comment", "--comment", policyRoutingGcpPostRoutingComment},
			},
			ipt,
		},
		IPTablesRuleConfig{
			IPTablesChainSpec{
				TableName:      tableMangle,
				ChainName:      postRoutingChain,
				IsDefaultChain: true,
				IPT:            ipt,
			},
			[]IPTablesRuleSpec{
				[]string{"-j", gcpPostRoutingChain, "-m", "comment", "--comment", policyRoutingPostRoutingComment},
			},
			ipt,
		},
		IPRouteConfig{
			Route: netlink.Route{
				Table:     customRouteTable,
				LinkIndex: defaultLinkIndex,
				Gw:        defaultGateway,
				Dst:       nil,
			},
			RouteAdd: netlink.RouteAdd,
			RouteDel: netlink.RouteDel,
		},
		IPRuleConfig{
			Rule: netlink.Rule{
				Mark:              hairpinMark,
				Mask:              hairpinMask,
				Table:             unix.RT_TABLE_MAIN,
				Priority:          hairpinRulePriority,
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Goto:              -1,
				Flow:              -1,
			},
			RuleAdd:  netlink.RuleAdd,
			RuleDel:  netlink.RuleDel,
			RuleList: netlink.RuleList,
		},
		IPRuleConfig{
			Rule: netlink.Rule{
				IifName:           localNetdev,
				Table:             unix.RT_TABLE_MAIN,
				Priority:          localRulePriority,
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Mark:              -1,
				Mask:              -1,
				Goto:              -1,
				Flow:              -1,
			},
			RuleAdd:  netlink.RuleAdd,
			RuleDel:  netlink.RuleDel,
			RuleList: netlink.RuleList,
		},
		IPRuleConfig{
			Rule: netlink.Rule{
				IifName:           defaultNetdev,
				Invert:            true,
				Table:             customRouteTable,
				Priority:          policyRoutingRulePriority,
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Mark:              -1,
				Mask:              -1,
				Goto:              -1,
				Flow:              -1,
			},
			RuleAdd:  netlink.RuleAdd,
			RuleDel:  netlink.RuleDel,
			RuleList: netlink.RuleList,
		},
	}
}
