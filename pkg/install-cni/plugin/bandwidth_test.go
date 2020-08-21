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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	cniTemplateBandwidth = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
    {
      "type": "ptp"
    }@cniBandwidthPlugin
  ]
}
`
	cniConfigBandwidthGolden = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
    {
      "type": "ptp"
    },
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    }
  ]
}
`

	cniTemplateBandwidthNoKey = `
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
	cniConfigNoBandwidthGolden = cniTemplateBandwidthNoKey
)

func TestBandwidthInstaller(t *testing.T) {
	cases := []struct {
		name              string
		enabled           bool
		binExists         bool
		cniConfigTemplate string
		expectedCNIConfig string
	}{
		{
			name:              "not enabled key does not exist",
			enabled:           false,
			cniConfigTemplate: cniTemplateBandwidthNoKey,
			expectedCNIConfig: cniConfigNoBandwidthGolden,
		},
		{
			name:              "not enabled key exists",
			enabled:           false,
			cniConfigTemplate: cniTemplateBandwidth,
			expectedCNIConfig: cniConfigNoBandwidthGolden,
		},
		{
			name:              "enabled key and bin do not exist",
			enabled:           true,
			binExists:         false,
			cniConfigTemplate: cniTemplateBandwidthNoKey,
			expectedCNIConfig: cniConfigNoBandwidthGolden,
		},
		{
			name:              "enabled key exists bin does not exist",
			enabled:           true,
			binExists:         false,
			cniConfigTemplate: cniTemplateBandwidth,
			expectedCNIConfig: cniConfigNoBandwidthGolden,
		},
		{
			name:              "enabled key does not exist bin exists",
			enabled:           true,
			binExists:         true,
			cniConfigTemplate: cniTemplateBandwidthNoKey,
			expectedCNIConfig: cniConfigNoBandwidthGolden,
		},
		{
			name:              "enabled key and bin exist",
			enabled:           true,
			binExists:         true,
			cniConfigTemplate: cniTemplateBandwidth,
			expectedCNIConfig: cniConfigBandwidthGolden,
		},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Create temp directory for files
			tempDir, err := ioutil.TempDir("", fmt.Sprintf("test-case-%d-", i))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(tempDir); err != nil {
					t.Fatal(err)
				}
			}()

			if c.binExists {
				if _, err := os.Create(filepath.Join(tempDir, "bandwidth")); err != nil {
					t.Fatal(err)
				}
			}

			in := NewBandwidthInstaller(c.enabled, tempDir, &c.cniConfigTemplate)
			assert.NoError(t, in.Run())

			assert.Equal(t, c.expectedCNIConfig, c.cniConfigTemplate)
			checkJSONFormat(t, c.cniConfigTemplate)
		})
	}
}
