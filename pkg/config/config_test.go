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
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestSysctlConfigEnsure(t *testing.T) {
	mSysctl := make(map[string]string)

	c := SysctlConfig{
		Key:          "net.ipv4.conf.all.rp_filter",
		Value:        "2",
		DefaultValue: "1",
		SysctlFunc: func(name string, params ...string) (string, error) {
			mSysctl[name] = params[0]
			return "", nil
		},
	}

	c.Ensure(true)
	if v := mSysctl["net.ipv4.conf.all.rp_filter"]; v == "" || v != "2" {
		t.Error("failed to Ensure sysctlConfig rule")
	}

	c.Ensure(false)
	if v := mSysctl["net.ipv4.conf.all.rp_filter"]; v == "" || v != "1" {
		t.Error("failed to disable sysctlConfig rule")
	}
}

func TestIPRouteConfigEnsure(t *testing.T) {
	r := IPRouteConfig{
		Route:    netlink.Route{},
		RouteAdd: func(route *netlink.Route) error { return os.ErrExist },
		RouteDel: func(route *netlink.Route) error { return syscall.Errno(syscall.ESRCH) },
	}
	if err := r.Ensure(true); err != nil {
		t.Error("ipRouteConfig.Ensure(true) should ingore the os.ErrExist Error.")
	}
	if err := r.Ensure(false); err != nil {
		t.Error("ipRouteConfig.Ensure(false) should ingore the syscall.ESRCH Error.")
	}
}

func TestIPRuleConfigEnsure(t *testing.T) {
	ruleList := []netlink.Rule{
		netlink.Rule{SuppressIfgroup: -1, SuppressPrefixlen: -1, Mark: -1, Mask: -1, Goto: -1},
		netlink.Rule{SuppressIfgroup: 1, SuppressPrefixlen: 2, Mark: -1, Mask: -1, Goto: -1},
		netlink.Rule{SuppressIfgroup: -1, SuppressPrefixlen: -1, Mark: -1, Mask: -1, Goto: -1},
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
		t.Errorf("IPRuleConfig.count() return wrong count.")
	}
	if count, _ := ipRule.count(); len(ruleList) != 3 || count != 2 {
		t.Error("ruleList should contains 3 rules")
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

type MockIPtable struct {
	iptCache map[string][]string
}

func (i MockIPtable) NewChain(table, chain string) error {
	if _, ok := i.iptCache[chain]; !ok {
		i.iptCache[chain] = make([]string, 0, 5)
	}
	return nil
}

func (i MockIPtable) ClearChain(table, chain string) error {
	i.iptCache[chain] = make([]string, 0, 5)
	return nil
}
func (i MockIPtable) DeleteChain(table, chain string) error {
	delete(i.iptCache, chain)
	return nil
}

func (i MockIPtable) AppendUnique(table, chain string, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	for _, r := range i.iptCache[chain] {
		if r == rule {
			return nil
		}
	}
	i.iptCache[chain] = append(i.iptCache[chain], rule)
	return nil
}
func (i MockIPtable) Delete(table, chain string, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	for index, r := range i.iptCache[chain] {
		if r == rule {
			i.iptCache[chain] = append(i.iptCache[chain][:index], i.iptCache[chain][index+1:]...)
			return nil
		}
	}
	return nil
}

func TestIPTablesRuleConfig(t *testing.T) {
	mockIpt := MockIPtable{
		iptCache: make(map[string][]string),
	}
	iptableRule1 := IPTablesRuleConfig{
		IPTablesChainSpec{
			TableName:      "mangle",
			ChainName:      "postRoutingChain",
			IsDefaultChain: true,
			Ipt:            mockIpt,
		},
		[]IPTablesRuleSpec{
			[]string{"rule1", "-m", "-j"},
			[]string{"rule2", "-m", "-j"},
		},
		mockIpt,
	}
	iptableRule2 := IPTablesRuleConfig{
		IPTablesChainSpec{
			TableName:      "mangle",
			ChainName:      "postRoutingChain",
			IsDefaultChain: true,
			Ipt:            mockIpt,
		},
		[]IPTablesRuleSpec{
			[]string{"rule1", "-m", "-j"},
			[]string{"rule3", "-m", "-j"},
		},
		mockIpt,
	}
	iptableRule3 := IPTablesRuleConfig{
		IPTablesChainSpec{
			TableName:      "mangle",
			ChainName:      "gcpPostRoutingChain",
			IsDefaultChain: false,
			Ipt:            mockIpt,
		},
		[]IPTablesRuleSpec{
			[]string{"rule1", "-m", "-j"},
			[]string{"rule2", "-m", "-j"},
		},
		mockIpt,
	}
	iptableRule1.Ensure(true)
	iptableRule2.Ensure(true)
	iptableRule3.Ensure(true)
	if len(mockIpt.iptCache) != 2 {
		t.Error("MockIPtable contains 2 chains")
	}
	if len(mockIpt.iptCache["postRoutingChain"]) != 3 || len(mockIpt.iptCache["gcpPostRoutingChain"]) != 2 {
		t.Errorf("MockIPtable postRoutingChain should contain 3 chains, but contains: %v", mockIpt.iptCache["postRoutingChain"])
		t.Errorf("MockIPtable gcpPostRoutingChain should contain 2 chains, but contains: %v", mockIpt.iptCache["gcpPostRoutingChain"])
	}
	iptableRule2.Ensure(false)
	iptableRule3.Ensure(false)

	if _, ok := mockIpt.iptCache["gcpPostRoutingChain"]; ok {
		t.Error("Ensure should delete IsDefaultChain: false chain.")
	}

	if _, ok := mockIpt.iptCache["postRoutingChain"]; !ok {
		t.Error("Ensure should keep IsDefaultChain: true chain.")
	}

	/*
		// This is a bug, the chain should contain 2 rule.
		if len(mockIpt.iptCache["postRoutingChain"]) != 2 {
			t.Error("Ensure should keep 2 rule for iptableRule1.")
		}
	*/

	iptableRule1.Ensure(false)
	if len(mockIpt.iptCache["postRoutingChain"]) != 0 {
		t.Error("Ensure should keep 0 rule for iptableRule1.")
	}
}
