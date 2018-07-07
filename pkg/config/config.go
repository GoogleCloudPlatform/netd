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
	Ensure(on bool) error
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

type IPTablesChainSpec struct {
	ChainName, TableName string
}

type IPTablesRuleSpec []string

type IPTablesRuleConfig struct {
	IPTablesChainSpec
	RuleSpec IPTablesRuleSpec
}

type IPTablesChainConfig struct {
	IPTablesChainSpec
	RuleSpecs []IPTablesRuleSpec
}

var ipt *iptables.IPTables

func init() {
	var err error
	if ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4); err != nil {
		glog.Errorf("failed to initialize iptables (ipv4)")
	}
}

func (s SysctlConfig) Ensure(on bool) error {
	var value string
	if on {
		value = s.Value
	} else {
		value = s.DefaultValue
	}

	_, err := sysctl.Sysctl(s.Key, value)
	return err
}

func (r IPRouteConfig) Ensure(on bool) error {
	var err error
	if on {
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

func (r IPRuleConfig) Ensure(on bool) error {
	var err error
	if on {
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

func (r IPTablesRuleConfig) Ensure(on bool) error {
	if on {
		return ipt.AppendUnique(r.TableName, r.ChainName, r.RuleSpec...)
	}

	if err := ipt.Delete(r.TableName, r.ChainName, r.RuleSpec...); err != nil {
		if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 2 {
			return err
		}
	}
	return nil
}

func (c IPTablesChainConfig) Ensure(on bool) error {
	var err error
	if on {
		if err := ipt.NewChain(c.TableName, c.ChainName); err != nil {
			if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
				glog.Errorf("failed to create chain %s in table %s: %v", c.ChainName, c.TableName, err)
				return err
			}
		}

		for _, rs := range c.RuleSpecs {
			err = ipt.AppendUnique(c.TableName, c.ChainName, rs...)
			if err != nil {
				glog.Errorf("failed to append rule %v in table %s chain %s: %v", rs, c.TableName, c.ChainName, err)
				return err
			}
		}
	} else {
		err = ipt.ClearChain(c.TableName, c.ChainName)
		if err != nil {
			glog.Errorf("failed to clean chain %s in table %s: %v", c.ChainName, c.TableName, err)
			return err
		}

		if err = ipt.DeleteChain(c.TableName, c.ChainName); err != nil {
			if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
				glog.Errorf("failed to delete chain %s in table %s: %v", c.ChainName, c.TableName, err)
				return err
			}
		}
	}
	return nil
}
