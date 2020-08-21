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

	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
	"github.com/GoogleCloudPlatform/netd/internal/systemutil"
)

// Config interface
type Config interface {
	Ensure(enabled bool) error
}

// Set defines the set of Config
type Set struct {
	Enabled     bool
	FeatureName string
	Configs     []Config
}

// SysctlConfig defines sysctl config
type SysctlConfig struct {
	Key, Value, DefaultValue string
	SysctlFunc               systemutil.SysctlFunc
}

type routeAdder func(route *netlink.Route) error
type routeDeler func(route *netlink.Route) error

// IPRouteConfig defines route config
type IPRouteConfig struct {
	Route    netlink.Route
	RouteAdd routeAdder
	RouteDel routeDeler
}

type ruleAdder func(rule *netlink.Rule) error
type ruleDeler func(rule *netlink.Rule) error
type ruleLister func(family int) ([]netlink.Rule, error)

// IPRuleConfig defines the config for ip rule
type IPRuleConfig struct {
	Rule     netlink.Rule
	RuleAdd  ruleAdder
	RuleDel  ruleDeler
	RuleList ruleLister
}

type IPTablesRulesConfig struct {
	Spec ipt.IPTablesSpec
	// If IsDefaultChain is true (system default chain), don't delete it
	IsDefaultChain bool
}

// Ensure SysctlConfig
func (s SysctlConfig) Ensure(enabled bool) error {
	var value string
	if enabled {
		value = s.Value
	} else {
		value = s.DefaultValue
	}
	_, err := s.SysctlFunc(s.Key, value)
	return err
}

// Ensure IPRouteConfig
func (r IPRouteConfig) Ensure(enabled bool) error {
	var err error
	if enabled {
		err = r.RouteAdd(&r.Route)
		if os.IsExist(err) {
			err = nil
		}
	} else if err = r.RouteDel(&r.Route); err != nil && err.(syscall.Errno) == syscall.ESRCH {
		err = nil
	}

	return err
}

// Ensure IPRuleConfig
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
		glog.Errorf("failed to get IP rule count for rule: %v, error: %v", r.Rule, err)
		return err
	}

	for ruleCount != ensureCount {
		if ruleCount > ensureCount {
			if err = r.RuleDel(&r.Rule); err != nil {
				glog.Errorf("failed to delete duplicated ip rule: %v, error: %v", r.Rule, err)
			}
			ruleCount--
		} else {
			err = r.RuleAdd(&r.Rule)
			if err != nil {
				if os.IsExist(err) {
					err = nil
				} else {
					glog.Errorf("failed to add ip rule: %v, error: %v", r.Rule, err)
				}
			}
			ruleCount++
		}
	}
	return err
}

func (r IPRuleConfig) count() (int, error) {
	rules, err := r.RuleList(unix.AF_INET)
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

// Ensure IPTablesRulesConfig
func (r IPTablesRulesConfig) Ensure(enabled bool) error {
	var err error
	if err = r.ensureChain(enabled); err != nil {
		return err
	}

	// Ensure chain rules
	if enabled {
		for _, rs := range r.Spec.Rules {
			err = r.Spec.IPT.AppendUnique(r.Spec.TableName, r.Spec.ChainName, rs...)
			if err != nil {
				glog.Errorf("failed to append rule %v in table %s chain %s: %v", rs, r.Spec.TableName, r.Spec.ChainName, err)
				return err
			}
		}
	} else if r.IsDefaultChain {
		// Only delete rules added to system default chains.
		// Non-system default chains should have already been deleted so no need to clear the rules.
		for _, rs := range r.Spec.Rules {
			if err := r.Spec.IPT.Delete(r.Spec.TableName, r.Spec.ChainName, rs...); err != nil {
				if eerr, eok := err.(ipt.Error); !eok || !eerr.IsNotExist() {
					// Error not caused by a nonexistent chain/rule
					return err
				}
			}
		}
	}
	return nil
}

func (r IPTablesRulesConfig) ensureChain(enabled bool) error {
	var err error
	if enabled {
		if err = r.Spec.IPT.NewChain(r.Spec.TableName, r.Spec.ChainName); err != nil {
			if eerr, eok := err.(ipt.Error); !eok || eerr.ExitStatus() != 1 {
				// Error not caused by already existent chain
				return err
			}
		}
	} else if !r.IsDefaultChain {
		err = r.Spec.IPT.ClearChain(r.Spec.TableName, r.Spec.ChainName)
		if err != nil {
			glog.Errorf("failed to clear chain %s in table %s: %v", r.Spec.TableName, r.Spec.ChainName, err)
			return err
		}
		if err = r.Spec.IPT.DeleteChain(r.Spec.TableName, r.Spec.ChainName); err != nil {
			if eerr, eok := err.(ipt.Error); !eok || !eerr.IsNotExist() {
				// Error not caused by a nonexistent chain
				glog.Errorf("failed to delete chain %s in table %s: %v", r.Spec.TableName, r.Spec.ChainName, err)
				return err
			}
		}
	}
	return nil
}
