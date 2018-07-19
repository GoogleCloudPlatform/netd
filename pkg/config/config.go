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

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
)

// Config can ensure kernel settings
type Config interface {
	Ensure(enabled bool) error
}

// Set holds Configs for a feature
type Set struct {
	Enabled     bool
	FeatureName string
	Configs     []Config
}

type sysctlConfig struct {
	key, value, defaultValue string
}

type ipRouteConfig struct {
	route netlink.Route
}

type ipRuleConfig struct {
	rule netlink.Rule
}

type ipTablesRuleSpec []string

type ipTablesChainSpec struct {
	tableName, chainName string
	isDefaultChain       bool // Is a System default chain, if yes, we won't delete it.
}

type ipTablesRuleConfig struct {
	spec      ipTablesChainSpec
	ruleSpecs []ipTablesRuleSpec
}

var ipt *iptables.IPTables

func init() {
	var err error
	if ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4); err != nil {
		glog.Errorf("failed to initialize iptables")
	}
}

func (s sysctlConfig) Ensure(enabled bool) error {
	var value string
	if enabled {
		value = s.value
	} else {
		value = s.defaultValue
	}
	_, err := sysctl.Sysctl(s.key, value)
	return err
}

func (r ipRouteConfig) Ensure(enabled bool) error {
	var err error
	if enabled {
		err = netlink.RouteAdd(&r.route)
		if os.IsExist(err) {
			err = nil
		}
	} else {
		if err = netlink.RouteDel(&r.route); err != nil && err.(syscall.Errno) == syscall.ESRCH {
			err = nil
		}
	}

	return err
}

func (r ipRuleConfig) Ensure(enabled bool) error {
	var err error
	if enabled {
		err = netlink.RuleAdd(&r.rule)
		if os.IsExist(err) {
			err = nil
		}
	} else {
		if err = netlink.RuleDel(&r.rule); err != nil && err.(syscall.Errno) == syscall.ENOENT {
			err = nil
		}
	}

	return err
}

func (c ipTablesChainSpec) ensure(enabled bool) error {
	var err error
	if enabled {
		if err = ipt.NewChain(c.tableName, c.chainName); err != nil {
			if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
				return err
			}
		}
	} else {
		if !c.isDefaultChain {
			err = ipt.ClearChain(c.tableName, c.chainName)
			if err != nil {
				glog.Errorf("failed to clean chain %s in table %s: %v", c.tableName, c.chainName, err)
				return err
			}
			if err = ipt.DeleteChain(c.tableName, c.chainName); err != nil {
				if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
					glog.Errorf("failed to delete chain %s in table %s: %v", c.tableName, c.chainName, err)
					return err
				}
			}
		}
	}
	return nil
}

func (r ipTablesRuleConfig) Ensure(enabled bool) error {
	var err error
	if err = r.spec.ensure(enabled); err != nil {
		return err
	}
	if enabled {
		for _, rs := range r.ruleSpecs {
			err = ipt.AppendUnique(r.spec.tableName, r.spec.chainName, rs...)
			if err != nil {
				glog.Errorf("failed to append rule %v in table %s chain %s: %v", rs, r.spec.tableName, r.spec.chainName, err)
				return err
			}
		}
	} else {
		if r.spec.isDefaultChain {
			for _, rs := range r.ruleSpecs {
				if err := ipt.Delete(r.spec.tableName, r.spec.chainName, rs...); err != nil {
					if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 2 {
						// TODO: better handling the error
						if !strings.Contains(eerr.Error(), "No chain/target/match") {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}
