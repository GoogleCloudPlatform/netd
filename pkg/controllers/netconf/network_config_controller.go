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
	onConfigs           []config.Config
	offConfigs          []config.Config
}

const reconcileInterval = 10 * time.Second

func NewNetworkConfigController(enablePolicyRouting, enableMasquerade bool) *NetworkConfigController {
	var onConfigs, offConfigs []config.Config

	if enablePolicyRouting {
		onConfigs = append(onConfigs, config.PolicyRoutingConfig...)
	} else {
		offConfigs = append(offConfigs, config.PolicyRoutingConfig...)
	}

	if enableMasquerade {
		onConfigs = append(onConfigs, config.MasqueradeConfig...)
	} else {
		offConfigs = append(offConfigs, config.MasqueradeConfig...)
	}

	return &NetworkConfigController{
		enablePolicyRouting: enablePolicyRouting,
		enableMasquerade:    enableMasquerade,
		onConfigs:           onConfigs,
		offConfigs:          offConfigs,
	}
}

func (nc *NetworkConfigController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			nc.ensure()
		}
	}
}

func (nc *NetworkConfigController) ensure() {
	for on, configs := range map[bool]*[]config.Config{
		true:  &nc.onConfigs,
		false: &nc.offConfigs} {
		for _, c := range *configs {
			glog.V(4).Infof("Ensure %v as %v", reflect.ValueOf(c), on)
			if err := c.Ensure(on); err != nil {
				glog.Errorf("failed to ensure %v as %v: %v", reflect.ValueOf(c), on, err)
			}
		}

	}
}
