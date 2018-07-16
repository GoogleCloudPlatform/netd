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

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
)

type Config interface {
	Ensure(enabled bool) error
}

type ConfigSet struct {
	Enabled     bool
	FeatureName string
	Configs     []Config
}

type SysctlConfig struct {
	Key, Value, DefaultValue string
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

func (s SysctlConfig) Ensure(enabled bool) error {
	var value string
	if enabled {
		value = s.Value
	} else {
		value = s.DefaultValue
	}
	_, err := sysctl.Sysctl(s.Key, value)
	return err
}

func (r IPRouteConfig) Ensure(enabled bool) error {
	var err error
	if enabled {
		err = netlink.RouteAdd(&r.Route)
		if os.IsExist(err) {
			err = nil
		}
	} else {
		if err = netlink.RouteDel(&r.Route); err != nil && err.(syscall.Errno) == syscall.ESRCH {
			err = nil
		}
	}

	return err
}

func (r IPRuleConfig) Ensure(enabled bool) error {
	var err error
	if enabled {
		err = netlink.RuleAdd(&r.Rule)
		if os.IsExist(err) {
			err = nil
		}
	} else {
		if err = netlink.RuleDel(&r.Rule); err != nil && err.(syscall.Errno) == syscall.ENOENT {
			err = nil
		}
	}

	return err
}

func (c IPTablesChainConfig) Ensure(enabled bool) error {
	if err := ipt.NewChain(c.TableName, c.ChainName); err != nil {
		if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
			return err
		}
	}
	return nil
}

func (r IPTablesRuleConfig) Ensure(enabled bool) error {
	return ipt.AppendUnique(r.TableName, r.ChainName, r.RuleSpec...)
}
