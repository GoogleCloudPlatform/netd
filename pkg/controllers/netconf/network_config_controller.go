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

	"github.com/GoogleCloudPlatform/netd/pkg/config"
	"github.com/golang/glog"
)

// NetworkConfigController manages kernel settings
type NetworkConfigController struct {
	configSets []*config.Set
}

// NewNetworkConfigController creates a new NetworkConfigController
func NewNetworkConfigController(enablePolicyRouting, enableMasquerade bool) *NetworkConfigController {
	var configSets []*config.Set

	configSets = append(configSets, &config.PolicyRoutingConfigSet)
	configSets = append(configSets, &config.MasqueradeConfigSet)

	if enablePolicyRouting {
		config.PolicyRoutingConfigSet.Enabled = true
	}

	if enableMasquerade {
		config.MasqueradeConfigSet.Enabled = true
	}

	return &NetworkConfigController{
		configSets: configSets,
	}
}

// Run executes main loop of NetworkConfigController
func (n *NetworkConfigController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-stopCh:
			return
		case <-time.After(10 * time.Second):
			n.ensure()
		}
	}
}

func (n *NetworkConfigController) ensure() {
	for _, cs := range n.configSets {
		for _, c := range cs.Configs {
			if err := c.Ensure(cs.Enabled); err != nil {
				glog.Errorf("found an error for %v: %v when ensuring %v", cs.FeatureName, err, reflect.ValueOf(c))
			}
		}
	}
}
