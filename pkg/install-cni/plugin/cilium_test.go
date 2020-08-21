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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	cniTemplateCilium = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
    {
      "type": "ptp"
    }@cniCiliumPlugin
  ]
}
`
	cniConfigCiliumGolden = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
    {
      "type": "ptp"
    },
    {
      "type": "cilium-cni"
    }
  ]
}
`
	cniTemplateCiliumNoKey = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
    {
      "type": "ptp"
    }
  ]
}
`
	cniConfigNoCiliumGolden = cniTemplateCiliumNoKey
)

func TestCiliumInstaller(t *testing.T) {
	cases := []struct {
		name              string
		enabled           bool
		cniConfigTemplate string
		expectedCNIConfig string
	}{
		{
			name:              "not enabled key does not exist",
			enabled:           false,
			cniConfigTemplate: cniTemplateCiliumNoKey,
			expectedCNIConfig: cniConfigNoCiliumGolden,
		},
		{
			name:              "not enabled key exists",
			enabled:           false,
			cniConfigTemplate: cniTemplateCilium,
			expectedCNIConfig: cniConfigNoCiliumGolden,
		},
		{
			name:              "enabled key does not exist",
			enabled:           true,
			cniConfigTemplate: cniTemplateCiliumNoKey,
			expectedCNIConfig: cniConfigNoCiliumGolden,
		},
		{
			name:              "enabled key exists",
			enabled:           true,
			cniConfigTemplate: cniTemplateCilium,
			expectedCNIConfig: cniConfigCiliumGolden,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := NewCiliumInstaller(c.enabled, &c.cniConfigTemplate)
			assert.NoError(t, in.Run())

			assert.Equal(t, c.expectedCNIConfig, c.cniConfigTemplate)
			checkJSONFormat(t, c.cniConfigTemplate)
		})
	}
}
