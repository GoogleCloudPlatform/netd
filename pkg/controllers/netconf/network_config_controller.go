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

package netconf

import (
	"reflect"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/version"

	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/netd/pkg/config"
	"github.com/GoogleCloudPlatform/netd/pkg/kernel"
)

const (
	brokenLocalUDPKernelVersionStart = "6.6.57"
)

// NetworkConfigController defines the controller
type NetworkConfigController struct {
	configSet         []*config.Set
	reconcileInterval time.Duration
}

// NewNetworkConfigController creates a new NetworkConfigController
func NewNetworkConfigController(enablePolicyRouting, enableSourceValidMark, excludeDNS bool, reconcileInterval time.Duration) *NetworkConfigController {
	var configSet []*config.Set

	configSet = append(configSet, &config.PolicyRoutingConfigSet)

	if enablePolicyRouting {
		config.PolicyRoutingConfigSet.Enabled = true
	}
	if enableSourceValidMark {
		configSet[0].Configs = append(configSet[0].Configs, config.SourceValidMarkConfig)
	}
	if excludeDNS {
		configSet[0].Configs = append(configSet[0].Configs, config.ExcludeDNSIPRuleConfigs...)
	}
	kernelVersion, err := kernel.GetVersion()
	if err != nil {
		glog.Errorf("Could not check kernel version: %v. Skip installing UDP exempt rule.", err)
	} else {
		glog.Infof("Kernel version detected: %v.", kernelVersion)
		if kernelVersion.AtLeast(version.MustParseGeneric(brokenLocalUDPKernelVersionStart)) {
			glog.Infof("Kernel version is impacted by a known issue (start version: %v). Including an IP rule to exempt UDP traffic.", brokenLocalUDPKernelVersionStart)
			configSet[0].Configs = append(configSet[0].Configs, config.ExcludeUDPIPRuleConfig)
		}
	}

	return &NetworkConfigController{
		configSet:         configSet,
		reconcileInterval: reconcileInterval,
	}
}

// Run runs the NetworkConfigController
func (n *NetworkConfigController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	n.printConfig()

	for {
		n.ensure()

		select {
		case <-stopCh:
			return
		case <-time.After(n.reconcileInterval):
			continue
		}
	}
}

func (n *NetworkConfigController) ensure() {
	for _, cs := range n.configSet {
		for _, c := range cs.Configs {
			if err := c.Ensure(cs.Enabled); err != nil {
				glog.Errorf("found an error for %v: %v when ensuring %v", cs.FeatureName, err, reflect.ValueOf(c))
			}
		}
	}
}

func (n *NetworkConfigController) printConfig() {
	glog.Infof("**** NetworkConfigController configurations ****")
	for _, cs := range n.configSet {
		if !cs.Enabled {
			continue
		}
		glog.Infof("** FeatureName: %s is enabled **", cs.FeatureName)
		for _, c := range cs.Configs {
			glog.Infof("%v", c)
		}
	}
}
