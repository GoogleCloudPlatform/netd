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
	"github.com/vishvananda/netlink"

	"github.com/GoogleCloudPlatform/netd/internal/systemutil"
)

const (
	cniTemplatePTP = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
     {
  	  "type": "@cniType",
  	  "mtu": @mtu,
  	  "ipam": {
  		"type": "host-local",
  		"ranges": [
        @ipv4Subnet
  		]
  	  }
  	}
  ]
}
`
	cniConfigPTPFormat = `
{
  "cniVersion": "0.3.1",
  "name": "gke-pod-network",
  "plugins": [
     {
  	  "type": "%s",
  	  "mtu": %d,
  	  "ipam": {
  		"type": "host-local",
  		"ranges": [
          [
            {
              "subnet": "%s"
            }
          ]
  		]
  	  }
  	}
  ]
}
`
	cniTemplatePTPNoKeys = `
{
  "cniVersion": "0.3.1",
  "name": "pod-network",
  "plugins": [
     {
  	  "type": "custom-type",
  	  "mtu": 1500,
  	  "ipam": {
  		"type": "host-local",
  		"ranges": [
          [
            {
              "subnet": "POD_CIDR"
            }
          ]
  		]
  	  }
  	}
  ]
}
`
)

func TestPTPInstaller(t *testing.T) {
	cases := []struct {
		name         string
		noKeys       bool
		gkeBinExists bool
		podCIDR      string
		mtu          int
	}{
		{
			name:   "no keys",
			noKeys: true,
		},
		{
			name:         "gke bin does not exist",
			gkeBinExists: false,
			podCIDR:      "POD_CIDR",
			mtu:          0,
		},
		{
			name:         "gke exists",
			gkeBinExists: true,
			podCIDR:      "POD_CIDR",
			mtu:          1500,
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
			if c.gkeBinExists {
				if _, err := os.Create(filepath.Join(tempDir, "gke")); err != nil {
					t.Fatal(err)
				}
			}

			var expectedCNIConfig, cniConfigTemplate string
			if c.noKeys {
				expectedCNIConfig = cniTemplatePTPNoKeys
				cniConfigTemplate = cniTemplatePTPNoKeys
			} else {
				cniType := "ptp"
				if c.gkeBinExists {
					cniType = "gke"
				}
				mtu := c.mtu
				if mtu == 0 {
					mtu = defaultMTU
				}
				expectedCNIConfig = fmt.Sprintf(cniConfigPTPFormat, cniType, mtu, c.podCIDR)
				cniConfigTemplate = cniTemplatePTP
			}

			defaultNIC := systemutil.NIC{
				Link: netlink.LinkAttrs{
					MTU:  c.mtu,
					Name: "device",
				},
			}

			in := NewPTPInstaller(tempDir, c.podCIDR, defaultNIC, &cniConfigTemplate)
			assert.NoError(t, in.Run())

			assert.Equal(t, expectedCNIConfig, cniConfigTemplate)
			checkJSONFormat(t, cniConfigTemplate)
		})
	}
}
