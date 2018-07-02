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

type NetworkConfigController struct {
	enablePolicyRouting bool
	enableMasquerade    bool
	configs             []config.Config
}

func NewNetworkConfigController(enablePolicyRouting, enableMasquerade bool) *NetworkConfigController {
	var configs []config.Config

	if enablePolicyRouting {
		configs = append(configs, config.PolicyRoutingConfig...)
	}

	if enableMasquerade {
		configs = append(configs, config.MasqueradeConfig...)
	}

	return &NetworkConfigController{
		enablePolicyRouting: enablePolicyRouting,
		enableMasquerade:    enableMasquerade,
		configs:             configs,
	}
}

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
	for _, c := range n.configs {
		if err := c.Ensure(); err != nil {
			glog.Errorf("found an error: %v when ensuring %v", err, reflect.ValueOf(c))
		}
	}
}
