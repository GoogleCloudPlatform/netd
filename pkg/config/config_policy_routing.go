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
	"context"
	"fmt"
	"net"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	netutils "k8s.io/utils/net"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/GoogleCloudPlatform/netd/pkg/utils/nodeinfo"
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
	customRouteTable = 1
)

const (
	// Note that localTableRulePriority will be shared by multiple local rules.
	// As the ordering of them don't matter.
	localTableRulePriority = 70 + iota
	hairpinUDPRulePriority
	hairpinDNSRequestRulePriority
	hairpinDNSResponseRulePriority
	hairpinRulePriority
	localRulePriority
	policyRoutingRulePriority // The last priority is 76.
)

var (
	defaultGateway   net.IP
	defaultLinkIndex int
	defaultNetdev    string
	localNetdev      string
	loopbackDst      net.IPNet
	linkLocalNet     net.IPNet
	vethGatewayDst   net.IPNet
)

var (
	RouteGet    = netlink.RouteGet
	LinkByIndex = netlink.LinkByIndex
)

// PolicyRoutingConfigSet defines the Policy Routing rules
var PolicyRoutingConfigSet = Set{
	false,
	"PolicyRouting",
	nil,
}

// InitPolicyRouting performs necessary initialization for policy routing.
// It should be called before running the policy routing enforcement loop.
func InitPolicyRouting(ctx context.Context, clientset kubernetes.Interface, nodeName string) error {
	f := func(ip net.IP) (linkIndex int, netdev string, gw net.IP) {
		routes, err := RouteGet(ip)
		if err != nil {
			glog.Errorf("failed to get route for IP: %v (%v)", ip, err)
			return
		}
		gw = routes[0].Gw
		linkIndex = routes[0].LinkIndex

		l, err := LinkByIndex(linkIndex)
		if err != nil {
			glog.Errorf("failed to get the link by index: %v (%v)", linkIndex, err)
		}
		netdev = l.Attrs().Name
		return
	}
	defaultLinkIndex, defaultNetdev, defaultGateway = f(net.IPv4(8, 8, 8, 8))
	_, localNetdev, _ = f(net.IPv4(127, 0, 0, 1))
	loopbackDst = net.IPNet{
		IP:   net.IPv4(127, 0, 0, 0),
		Mask: net.CIDRMask(8, 32),
	}
	// Traffic to 169.254.0.0/16 should always be routed to the local table.
	// This is the link-local address space.
	linkLocalNet = net.IPNet{
		IP:   net.IPv4(169, 254, 0, 0),
		Mask: net.CIDRMask(16, 32),
	}

	if err := fillLocalRulesFromNode(ctx, clientset, nodeName); err != nil {
		return fmt.Errorf("configure local rule destinations from node: %w", err)
	}

	sysctlReversePathFilter := fmt.Sprintf("net.ipv4.conf.%s.rp_filter", defaultNetdev)
	hairpinMaskStr := fmt.Sprintf("0x%x", hairpinMask)
	PolicyRoutingConfigSet.Configs = append(PolicyRoutingConfigSet.Configs,
		SysctlConfig{
			Key:          sysctlReversePathFilter,
			Value:        "2",
			DefaultValue: "1",
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
				[]string{
					"-j", "CONNMARK", "--restore-mark", "--nfmask", hairpinMaskStr, "--ctmask", hairpinMaskStr,
					"-m", "comment", "--comment", policyRoutingGcpPreRoutingComment,
				},
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
					"-j", "CONNMARK", "--save-mark", "--nfmask", hairpinMaskStr, "--ctmask", hairpinMaskStr, "-m",
					"comment", "--comment", policyRoutingGcpPostRoutingComment},
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
	)

	glog.Info("Including local table rules.")
	PolicyRoutingConfigSet.Configs = append(PolicyRoutingConfigSet.Configs, LocalTableRuleConfigs...)

	return nil
}

func fillLocalRulesFromNode(ctx context.Context, clientset kubernetes.Interface, nodeName string) error {
	// Retrieve necessary IP info from the node object.
	var node *v1.Node
	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		var err error
		node, err = clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			glog.Errorf("Failed to get node %s: %v", nodeName, err)
			return false, nil
		}
		return true, nil
	}); err != nil {
		return err
	}

	nodeInternalIPs := []net.IP{}
	for _, address := range node.Status.Addresses {
		if !netutils.IsIPv4String(address.Address) ||
			address.Type != v1.NodeInternalIP {
			continue
		}
		nodeInternalIPs = append(nodeInternalIPs, net.ParseIP(address.Address))
	}
	if len(nodeInternalIPs) == 0 {
		return fmt.Errorf("no InternalIP found in node %s", nodeName)
	}
	for _, ip := range nodeInternalIPs {
		ipDst := net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
		LocalTableRuleConfigs = append(LocalTableRuleConfigs,
			newNodeInternalIPRuleConfig(ipDst))
	}

	var vethGatewayIP net.IP
	podCIDRs, err := nodeinfo.GetPodCIDRs(node)
	if err != nil {
		return err
	}
	for _, podCIDR := range podCIDRs {
		if !netutils.IsIPv4CIDRString(podCIDR) {
			continue
		}
		vethGatewayIP, _, err = net.ParseCIDR(podCIDR)
		if err != nil {
			return fmt.Errorf("parse podCIDR %s: %w", podCIDR, err)
		}
	}
	if vethGatewayIP == nil {
		return fmt.Errorf("no PodCIDR found in node %s", nodeName)
	}
	vethGatewayDst = net.IPNet{
		// vethGateway is the first usable IP from Pod CIDR.
		IP:   ip.NextIP(vethGatewayIP),
		Mask: net.CIDRMask(32, 32),
	}
	return nil
}

var SourceValidMarkConfig = SysctlConfig{
	Key:          sysctlSrcValidMark,
	Value:        "1",
	DefaultValue: "0",
	SysctlFunc:   sysctl.Sysctl,
}

var ExcludeDNSIPRuleConfigs = []Config{
	IPRuleConfig{
		Rule: netlink.Rule{
			Table:             unix.RT_TABLE_MAIN,
			Priority:          hairpinDNSRequestRulePriority,
			Dport:             netlink.NewRulePortRange(53, 53),
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
			Table:             unix.RT_TABLE_MAIN,
			Priority:          hairpinDNSResponseRulePriority,
			Sport:             netlink.NewRulePortRange(53, 53),
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

var ExcludeUDPIPRuleConfig = IPRuleConfig{
	Rule: netlink.Rule{
		Table:             unix.RT_TABLE_MAIN,
		Priority:          hairpinUDPRulePriority,
		IPProto:           unix.IPPROTO_UDP,
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
}

// LocalTableRuleConfigs are needed to enforce necessary traffic to go through
// the local routing table. This is required when our policy routing configs
// are installed with a high priority than the default local rule.
// Notably some additional configs will be rendered dynamically and appended
// during init time.
var LocalTableRuleConfigs = []Config{
	IPRuleConfig{
		Rule: netlink.Rule{
			Table:             unix.RT_TABLE_LOCAL,
			Priority:          localTableRulePriority,
			Dst:               &loopbackDst,
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
			Table:             unix.RT_TABLE_LOCAL,
			Priority:          localTableRulePriority,
			Dst:               &linkLocalNet,
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
			Table:             unix.RT_TABLE_LOCAL,
			Priority:          localTableRulePriority,
			Dst:               &vethGatewayDst,
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

func newNodeInternalIPRuleConfig(dst net.IPNet) IPRuleConfig {
	return IPRuleConfig{
		Rule: netlink.Rule{
			Table:             unix.RT_TABLE_LOCAL,
			Priority:          localTableRulePriority,
			Dst:               &dst,
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
	}
}
