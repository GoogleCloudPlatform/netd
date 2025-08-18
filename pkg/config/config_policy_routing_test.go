/*
Copyright 2025 Google Inc.

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
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFillLocalRulesFromNode(t *testing.T) {
	testCases := []struct {
		desc                string
		node                *v1.Node
		wantVethGatewayDst  net.IPNet
		wantNodeInternalIPs []net.IP
		wantErr             bool
	}{
		{
			desc: "working case with podCIDR",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: v1.NodeSpec{
					PodCIDR: "10.124.0.0/16",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "10.128.0.24",
						},
					},
				},
			},
			wantVethGatewayDst: net.IPNet{
				IP:   net.IPv4(10, 124, 0, 1),
				Mask: net.CIDRMask(32, 32),
			},
			wantNodeInternalIPs: []net.IP{
				net.IPv4(10, 128, 0, 24),
			},
			wantErr: false,
		},
		{
			desc: "working case with podCIDRs",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: v1.NodeSpec{
					PodCIDRs: []string{"10.124.0.0/16"},
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "10.128.0.24",
						},
					},
				},
			},
			wantVethGatewayDst: net.IPNet{
				IP:   net.IPv4(10, 124, 0, 1),
				Mask: net.CIDRMask(32, 32),
			},
			wantNodeInternalIPs: []net.IP{
				net.IPv4(10, 128, 0, 24),
			},
			wantErr: false,
		},
		{
			desc: "multiple InternalIPs",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: v1.NodeSpec{
					PodCIDR: "10.124.0.0/16",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "10.128.0.24",
						},
						{
							Type:    v1.NodeInternalIP,
							Address: "172.30.0.5",
						},
					},
				},
			},
			wantVethGatewayDst: net.IPNet{
				IP:   net.IPv4(10, 124, 0, 1),
				Mask: net.CIDRMask(32, 32),
			},
			wantNodeInternalIPs: []net.IP{
				net.IPv4(10, 128, 0, 24),
				net.IPv4(172, 30, 0, 5),
			},
			wantErr: false,
		},
		{
			desc: "missing PodCIDR",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "10.128.0.24",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "missing InternalIP",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: v1.NodeSpec{
					PodCIDR: "10.124.0.0/16",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeExternalIP,
							Address: "10.128.0.24",
						},
					},
				},
			},
			wantErr: true,
		},
	}
	originLocalTableRuleConfigs := LocalTableRuleConfigs
	for _, tc := range testCases {
		fakeClient := fake.NewSimpleClientset(tc.node)
		if err := fillLocalRulesFromNode(context.Background(), fakeClient, tc.node.Name); err != nil {
			if !tc.wantErr {
				t.Errorf("fillLocalRulesFromNode() error = %v", err)
			}
			continue
		}
		if !vethGatewayDst.IP.Equal(tc.wantVethGatewayDst.IP) {
			t.Errorf("fillLocalRulesFromNode() vethGatewayDst = %v, want %v", vethGatewayDst, tc.wantVethGatewayDst)
		}
		matchedNodeIPs := len(tc.wantNodeInternalIPs)
		for _, nodeInternalIP := range tc.wantNodeInternalIPs {
			for _, localRule := range LocalTableRuleConfigs {
				if localRule.(IPRuleConfig).Rule.Dst != nil && nodeInternalIP.Equal(localRule.(IPRuleConfig).Rule.Dst.IP) {
					matchedNodeIPs--
				}
			}
		}
		if matchedNodeIPs != 0 {
			t.Errorf("fillLocalRulesFromNode() matchedNodeIPDsts = %v, want %v. LocalTableRuleConfigs=%+v", matchedNodeIPs,
				len(tc.wantNodeInternalIPs), LocalTableRuleConfigs)
		}
		// Resetting local configs for testing purpose.
		LocalTableRuleConfigs = originLocalTableRuleConfigs
	}
}

func TestInitPolicyRouting(t *testing.T) {
	nodeName := "test-node"
	podCIDR := "10.0.0.0/24"
	internalIP := "192.168.1.100"

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: v1.NodeSpec{
			PodCIDR: podCIDR,
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Type:    v1.NodeInternalIP,
					Address: internalIP,
				},
			},
		},
	}
	fakeClient := fake.NewSimpleClientset(node)

	// Save original state and defer restoration.
	originalPolicyRoutingConfigSet := PolicyRoutingConfigSet
	originalLocalTableRuleConfigs := make([]Config, len(LocalTableRuleConfigs))
	copy(originalLocalTableRuleConfigs, LocalTableRuleConfigs)
	originalLinkLocalNet := linkLocalNet
	defer func() {
		PolicyRoutingConfigSet = originalPolicyRoutingConfigSet
		LocalTableRuleConfigs = originalLocalTableRuleConfigs
		linkLocalNet = originalLinkLocalNet
	}()

	// Reset global state for the test.
	PolicyRoutingConfigSet.Configs = nil
	loopbackDst = net.IPNet{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	linkLocalNet = net.IPNet{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)}
	vethGatewayDst = net.IPNet{}
	LocalTableRuleConfigs = []Config{
		newNodeInternalIPRuleConfig(loopbackDst),
		newNodeInternalIPRuleConfig(linkLocalNet),
		newNodeInternalIPRuleConfig(vethGatewayDst),
	}

	// Mock the dependencies
	originalRouteGet := RouteGet
	originalLinkByIndex := LinkByIndex
	defer func() {
		RouteGet = originalRouteGet
		LinkByIndex = originalLinkByIndex
	}()

	RouteGet = func(_ net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{Gw: net.IPv4(192, 168, 1, 1), LinkIndex: 2}}, nil
	}
	LinkByIndex = func(_ int) (netlink.Link, error) {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}, nil
	}

	numLocalRulesBefore := len(LocalTableRuleConfigs)

	err := InitPolicyRouting(context.Background(), fakeClient, nodeName)
	if err != nil {
		t.Fatalf("InitPolicyRouting() returned an unexpected error: %v", err)
	}

	if len(LocalTableRuleConfigs) != numLocalRulesBefore+1 {
		t.Fatalf("Expected %d local table rules, but got %d", numLocalRulesBefore+1, len(LocalTableRuleConfigs))
	}

	// there are 9 other configs + local table rules
	expectedNumConfigs := 9 + len(LocalTableRuleConfigs)
	if len(PolicyRoutingConfigSet.Configs) != expectedNumConfigs {
		t.Fatalf("Expected %d configs, but got %d", expectedNumConfigs, len(PolicyRoutingConfigSet.Configs))
	}

	// Check for the link-local rule
	foundLinkLocalRule := false
	expectedLinkLocalNet := "169.254.0.0/16"
	for _, config := range PolicyRoutingConfigSet.Configs {
		if ipRuleConfig, ok := config.(IPRuleConfig); ok {
			if ipRuleConfig.Rule.Table == unix.RT_TABLE_LOCAL && ipRuleConfig.Rule.Dst != nil && ipRuleConfig.Rule.Dst.String() == expectedLinkLocalNet {
				foundLinkLocalRule = true
			}
		}
	}

	if !foundLinkLocalRule {
		t.Errorf("Expected to find a rule for the link-local network (%s), but did not", expectedLinkLocalNet)
	}

	foundNodeInternalIPRule := false
	for _, config := range LocalTableRuleConfigs {
		if ipRuleConfig, ok := config.(IPRuleConfig); ok {
			if ipRuleConfig.Rule.Dst != nil && ipRuleConfig.Rule.Dst.IP.String() == internalIP {
				foundNodeInternalIPRule = true
			}
		}
	}
	if !foundNodeInternalIPRule {
		t.Errorf("Expected to find a rule for the node internal IP (%s), but did not", internalIP)
	}
}
