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
	customRouteTable    = 2
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

var PolicyRoutingConfig []Config

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

	PolicyRoutingConfig = []Config{
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
			RuleSpec: []string{"-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", hairpinMark, hairpinMask),
				"-j", "CONNMARK", "--save-mark"},
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
			RuleSpec: []string{"add", "fwmark", fmt.Sprintf("0x%x/0x%x", hairpinMark, hairpinMask),
				"table", "main", "pref", fmt.Sprintf("%d", hairpinRulePriority)},
		},
		IPRuleConfig{
			RuleSpec: []string{"add", "iif", localNetdev,
				"table", "main", "pref", fmt.Sprintf("%d", localRulePriority)}},
		IPRuleConfig{
			RuleSpec: []string{"add", "not", "iif", defaultNetdev,
				"table", fmt.Sprintf("%d", customRouteTable), "pref", fmt.Sprintf("%d", policyRoutingRulePriority)}},
	}
}
