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

package options

import (
	"time"

	"github.com/spf13/pflag"
)

// NetdConfig defines the netd config
type NetdConfig struct {
	EnablePolicyRouting bool
	ExcludeDNS          bool
	EnableMasquerade    bool
	ReconcileInterval   time.Duration
}

// NewNetdConfig creates a new netd config
func NewNetdConfig() *NetdConfig {
	return &NetdConfig{}
}

// AddFlags init flags from pflag
func (nc *NetdConfig) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&nc.EnablePolicyRouting, "enable-policy-routing", false,
		"Enable policy routing.")
	fs.BoolVar(&nc.ExcludeDNS, "exclude-dns", false,
		"Whether to exclude DNS traffic from policy routing.")
	fs.BoolVar(&nc.EnableMasquerade, "enable-masquerade", true,
		"[Deprecated]Enable masquerade.")
	fs.DurationVar(&nc.ReconcileInterval, "reconcile-interval-seconds", 10*time.Second,
		"Reconcile interval in seconds.")
}
