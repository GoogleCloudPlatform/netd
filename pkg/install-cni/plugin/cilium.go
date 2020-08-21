/*
Copyright 2020 Google Inc.

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

package plugin

import "strings"

const (
	ciliumPluginKey      = "@cniCiliumPlugin"
	ciliumPluginTemplate = `,
    {
      "type": "cilium-cni"
    }`
)

type CiliumInstaller struct {
	enabled           bool
	cniConfigTemplate *string
}

func NewCiliumInstaller(enabled bool, cniConfigTemplate *string) *CiliumInstaller {
	return &CiliumInstaller{
		enabled:           enabled,
		cniConfigTemplate: cniConfigTemplate,
	}
}

func (in *CiliumInstaller) Run() error {
	var ciliumPluginConfig string
	if in.enabled {
		ciliumPluginConfig = ciliumPluginTemplate
	}

	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, ciliumPluginKey, ciliumPluginConfig)

	return nil
}
