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
	"golang.org/x/sys/unix"
)

type Config interface {
	Ensure(enabled bool) error
}

type Set struct {
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

type IPTablesRuleSpec []string

type IPTablesChainSpec struct {
	TableName, ChainName string
	IsDefaultChain       bool // Is a System default chain, if yes, we won't delete it.
}

type IPTablesRuleConfig struct {
	Spec      IPTablesChainSpec
	RuleSpecs []IPTablesRuleSpec
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
	if enabled {
		return r.ensureHelper(1)
	}
	return r.ensureHelper(0)
}

func (r IPRuleConfig) ensureHelper(ensureCount int) error {
	var err error
	ruleCount, err := r.count()
	if err != nil {
		return err
	}

	for ruleCount != ensureCount {
		if ruleCount > ensureCount {
			if err = netlink.RuleDel(&r.Rule); err != nil {
				glog.Errorf("failed to delete duplicated ip rule: %v, error: %v", r.Rule, err)
			}
			ruleCount--
		} else {
			if err = netlink.RuleAdd(&r.Rule); os.IsExist(err) {
				err = nil
			}
			ruleCount++
		}
	}

	return err
}

func (r IPRuleConfig) count() (int, error) {
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, rule := range rules {
		if rule == r.Rule {
			count++
		}
	}
	return count, nil
}

func (c IPTablesChainSpec) ensure(enabled bool) error {
	var err error
	if enabled {
		if err = ipt.NewChain(c.TableName, c.ChainName); err != nil {
			if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
				return err
			}
		}
	} else {
		if !c.IsDefaultChain {
			err = ipt.ClearChain(c.TableName, c.ChainName)
			if err != nil {
				glog.Errorf("failed to clean chain %s in table %s: %v", c.TableName, c.ChainName, err)
				return err
			}
			if err = ipt.DeleteChain(c.TableName, c.ChainName); err != nil {
				if eerr, eok := err.(*iptables.Error); !eok || eerr.ExitStatus() != 1 {
					glog.Errorf("failed to delete chain %s in table %s: %v", c.TableName, c.ChainName, err)
					return err
				}
			}
		}
	}
	return nil
}

func (r IPTablesRuleConfig) Ensure(enabled bool) error {
	var err error
	if err = r.Spec.ensure(enabled); err != nil {
		return err
	}
	if enabled {
		for _, rs := range r.RuleSpecs {
			err = ipt.AppendUnique(r.Spec.TableName, r.Spec.ChainName, rs...)
			if err != nil {
				glog.Errorf("failed to append rule %v in table %s chain %s: %v", rs, r.Spec.TableName, r.Spec.ChainName, err)
				return err
			}
		}
	} else {
		if r.Spec.IsDefaultChain {
			for _, rs := range r.RuleSpecs {
				if err := ipt.Delete(r.Spec.TableName, r.Spec.ChainName, rs...); err != nil {
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
