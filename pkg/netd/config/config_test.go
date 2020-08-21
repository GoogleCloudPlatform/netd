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
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
	"github.com/GoogleCloudPlatform/netd/internal/ipt/ipttest"
	"github.com/GoogleCloudPlatform/netd/internal/systemutil/sysctltest"
)

func TestSysctlConfigEnsure(t *testing.T) {
	fakeSysctl := make(sysctltest.FakeSysctl)

	c := SysctlConfig{
		Key:          "net.ipv4.conf.all.rp_filter",
		Value:        "2",
		DefaultValue: "1",
		SysctlFunc:   fakeSysctl.Sysctl,
	}

	assert.NoError(t, c.Ensure(true))
	if v, err := fakeSysctl.Sysctl("net.ipv4.conf.all.rp_filter"); err != nil {
		t.Errorf("failed to ensure sysctlConfig rule: %v", err)
	} else {
		assert.Equal(t, c.Value, v, "failed to ensure sysctlConfig rule")
	}

	assert.NoError(t, c.Ensure(false))
	if v, err := fakeSysctl.Sysctl("net.ipv4.conf.all.rp_filter"); err != nil {
		t.Errorf("failed to disable sysctlConfig rule: %v", err)
	} else {
		assert.Equal(t, c.DefaultValue, v, "failed to disable sysctlConfig rule")
	}
}

func TestIPRouteConfigEnsure(t *testing.T) {
	r := IPRouteConfig{
		Route:    netlink.Route{},
		RouteAdd: func(route *netlink.Route) error { return os.ErrExist },
		RouteDel: func(route *netlink.Route) error { return syscall.ESRCH },
	}
	if err := r.Ensure(true); err != nil {
		t.Error("ipRouteConfig.Ensure(true) should ignore the os.ErrExist Error.")
	}
	if err := r.Ensure(false); err != nil {
		t.Error("ipRouteConfig.Ensure(false) should ignore the syscall.ESRCH Error.")
	}
}

func TestIPRuleConfigEnsure(t *testing.T) {
	ruleList := []netlink.Rule{
		{SuppressIfgroup: -1, SuppressPrefixlen: -1, Mark: -1, Mask: -1, Goto: -1},
		{SuppressIfgroup: 1, SuppressPrefixlen: 2, Mark: -1, Mask: -1, Goto: -1},
		{SuppressIfgroup: -1, SuppressPrefixlen: -1, Mark: -1, Mask: -1, Goto: -1},
	}

	mockRuleDel := func(rule *netlink.Rule) error {
		for i, r := range ruleList {
			if r == *rule {
				ruleList = append(ruleList[:i], ruleList[i+1:]...)
				return nil
			}
		}
		return nil
	}

	ipRule := IPRuleConfig{
		Rule:     netlink.Rule{SuppressIfgroup: -1, SuppressPrefixlen: -1, Mark: -1, Mask: -1, Goto: -1},
		RuleAdd:  func(rule *netlink.Rule) error { ruleList = append(ruleList, *rule); return nil },
		RuleDel:  mockRuleDel,
		RuleList: func(family int) ([]netlink.Rule, error) { return ruleList, nil },
	}
	if count, _ := ipRule.count(); count != 2 {
		t.Errorf("IPRuleConfig.count() should return 2.")
	}
	if len(ruleList) != 3 {
		t.Error("ruleList should contain 3 rules")
	}
	ipRule.Ensure(false)
	if count, _ := ipRule.count(); len(ruleList) != 1 || count != 0 {
		t.Error("failed to delete IPRule")
	}
	ipRule.Ensure(true)
	if count, _ := ipRule.count(); len(ruleList) != 2 || count != 1 {
		t.Error("failed to delete IPRule")
	}
}

func TestIPTablesRulesConfig(t *testing.T) {
	fakeIPT := ipttest.NewFakeIPTables("mangle")

	iptableRule1 := IPTablesRulesConfig{
		Spec: ipt.IPTablesSpec{
			TableName: "mangle",
			ChainName: "postRoutingChain",
			Rules: []ipt.IPTablesRule{
				[]string{"rule1", "-m", "-j"},
				[]string{"rule2", "-m", "-j"},
			},
			IPT: fakeIPT,
		},
		IsDefaultChain: true,
	}
	iptableRule2 := IPTablesRulesConfig{
		Spec: ipt.IPTablesSpec{
			TableName: "mangle",
			ChainName: "postRoutingChain",
			Rules: []ipt.IPTablesRule{
				[]string{"rule1", "-m", "-j"},
				[]string{"rule3", "-m", "-j"},
			},
			IPT: fakeIPT,
		},
		IsDefaultChain: true,
	}
	iptableRule3 := IPTablesRulesConfig{
		Spec: ipt.IPTablesSpec{
			TableName: "mangle",
			ChainName: "gcpPostRoutingChain",
			Rules: []ipt.IPTablesRule{
				[]string{"rule1", "-m", "-j"},
				[]string{"rule2", "-m", "-j"},
			},
			IPT: fakeIPT,
		},
		IsDefaultChain: false,
	}
	assert.NoError(t, iptableRule1.Ensure(true))
	assert.NoError(t, iptableRule2.Ensure(true))
	assert.NoError(t, iptableRule3.Ensure(true))
	if len(fakeIPT.Tables["mangle"].Rules) != 2 {
		t.Error("FakeIPTables contains 2 chains")
	}
	if len(fakeIPT.Tables["mangle"].Rules["postRoutingChain"]) != 3 || len(fakeIPT.Tables["mangle"].Rules["gcpPostRoutingChain"]) != 2 {
		t.Errorf("FakeIPTables postRoutingChain should contain 3 chains, but contains: %v", fakeIPT.Tables["mangle"].Rules["postRoutingChain"])
		t.Errorf("FakeIPTables gcpPostRoutingChain should contain 2 chains, but contains: %v", fakeIPT.Tables["mangle"].Rules["gcpPostRoutingChain"])
	}
	assert.NoError(t, iptableRule2.Ensure(false))
	assert.NoError(t, iptableRule3.Ensure(false))

	if _, ok := fakeIPT.Tables["mangle"].Rules["gcpPostRoutingChain"]; ok {
		t.Error("Ensure should delete IsDefaultChain: false chain.")
	}

	if _, ok := fakeIPT.Tables["mangle"].Rules["postRoutingChain"]; !ok {
		t.Error("Ensure should keep IsDefaultChain: true chain.")
	}

	assert.NoError(t, iptableRule1.Ensure(false))
	if len(fakeIPT.Tables["mangle"].Rules["postRoutingChain"]) != 0 {
		t.Error("Ensure should keep 0 rule for iptableRule1.")
	}
}
