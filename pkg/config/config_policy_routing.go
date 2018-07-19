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

	"github.com/golang/glog"
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

// PolicyRoutingConfigSet contains confgiurations for Policy Routing
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

	PolicyRoutingConfigSet.Configs = []Config{
		sysctlConfig{
			key:          sysctlReversePathFilter,
			value:        "2",
			defaultValue: "1",
		},
		sysctlConfig{
			key:          sysctlSrcValidMark,
			value:        "1",
			defaultValue: "0",
		},
		ipTablesRuleConfig{
			ipTablesChainSpec{
				tableName:      tableMangle,
				chainName:      gcpPreRoutingChain,
				isDefaultChain: false,
			},
			[]ipTablesRuleSpec{
				[]string{"-j", "CONNMARK", "--restore-mark", "-m", "comment", "--comment", policyRoutingGcpPreRoutingComment},
			},
		},
		ipTablesRuleConfig{
			ipTablesChainSpec{
				tableName:      tableMangle,
				chainName:      preRoutingChain,
				isDefaultChain: true,
			},
			[]ipTablesRuleSpec{
				[]string{"-j", gcpPreRoutingChain, "-m", "comment", "--comment", policyRoutingPreRoutingComment},
			},
		},
		ipTablesRuleConfig{
			ipTablesChainSpec{
				tableName:      tableMangle,
				chainName:      gcpPostRoutingChain,
				isDefaultChain: false,
			},
			[]ipTablesRuleSpec{
				[]string{"-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", hairpinMark, hairpinMask), "-j", "CONNMARK", "--save-mark", "-m", "comment", "--comment", policyRoutingGcpPostRoutingComment},
			},
		},
		ipTablesRuleConfig{
			ipTablesChainSpec{
				tableName:      tableMangle,
				chainName:      postRoutingChain,
				isDefaultChain: true,
			},
			[]ipTablesRuleSpec{
				[]string{"-j", gcpPostRoutingChain, "-m", "comment", "--comment", policyRoutingPostRoutingComment},
			},
		},
		ipRouteConfig{
			route: netlink.Route{
				Table:     customRouteTable,
				LinkIndex: defaultLinkIndex,
				Gw:        defaultGateway,
				Dst:       nil,
			},
		},
		ipRuleConfig{
			rule: netlink.Rule{
				Mark:              hairpinMark,
				Mask:              hairpinMask,
				Table:             unix.RT_TABLE_MAIN,
				Priority:          hairpinRulePriority,
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Goto:              -1,
				Flow:              -1,
			},
		},
		ipRuleConfig{
			rule: netlink.Rule{
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
		},
		ipRuleConfig{
			rule: netlink.Rule{
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
		},
	}
}
