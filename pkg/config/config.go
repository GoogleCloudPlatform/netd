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

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
)

type Config interface {
	Ensure(Enabled bool) error
}

type ConfigSet struct {
	Enabled     bool
	FeatureName string
	Configs     []Config
}

type SysctlConfig struct {
	Key, Value string
}

type IPRouteConfig struct {
	Route netlink.Route
}

type IPRuleConfig struct {
	Rule netlink.Rule
}

type IPTablesChainConfig struct {
	ChainName, TableName string
}

type IPTablesRuleConfig struct {
	ChainName, TableName string
	RuleSpec             []string
}

var ipt *iptables.IPTables

func init() {
	var err error
	if ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4); err != nil {
		glog.Errorf("failed to initialize iptables")
	}
}

func (s SysctlConfig) Ensure(Enabled bool) error {
	_, err := sysctl.Sysctl(s.Key, s.Value)
	return err
}

func (r IPRouteConfig) Ensure(Enabled bool) error {
	err := netlink.RouteAdd(&r.Route)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (r IPRuleConfig) Ensure(Enabled bool) error {
	err := netlink.RuleAdd(&r.Rule)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (c IPTablesChainConfig) Ensure(Enabled bool) error {
	if err := ipt.NewChain(c.TableName, c.ChainName); err != nil {
		if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
			return err
		}
	}
	return nil
}

func (r IPTablesRuleConfig) Ensure(Enabled bool) error {
	return ipt.AppendUnique(r.TableName, r.ChainName, r.RuleSpec...)
}
