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
	"path/filepath"
	"strings"

	"github.com/GoogleCloudPlatform/netd/internal/systemutil"

	"github.com/coreos/etcd/pkg/fileutil"
	"github.com/golang/glog"
)

const (
	cniTypeKey         = "@cniType"
	mtuKey             = "@mtu"
	ipv4SubnetKey      = "@ipv4Subnet"
	ipv4SubnetTemplate = `  [
            {
              "subnet": "%v"
            }
          ]`
)

const (
	gkeBinName = "gke"
	defaultMTU = 1460
)

type PTPInstaller struct {
	cniBinDir         string
	podCIDR           string
	defaultNIC        systemutil.NIC
	cniConfigTemplate *string
}

func NewPTPInstaller(cniBinDir, podCIDR string, defaultNIC systemutil.NIC, cniConfigTemplate *string) *PTPInstaller {
	return &PTPInstaller{
		cniBinDir:         cniBinDir,
		podCIDR:           podCIDR,
		defaultNIC:        defaultNIC,
		cniConfigTemplate: cniConfigTemplate,
	}
}

func (in *PTPInstaller) Run() error {
	var cniType string
	if gkeBinPath := filepath.Join(in.cniBinDir, gkeBinName); fileutil.Exist(gkeBinPath) {
		cniType = "gke"
	} else {
		cniType = "ptp"
	}
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, cniTypeKey, cniType)

	ipv4Subnet := fmt.Sprintf(ipv4SubnetTemplate, in.podCIDR)
	glog.Infof("Filling IPv4 subnet %v", ipv4Subnet)
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, ipv4SubnetKey, ipv4Subnet)

	mtu := in.getDefaultMTU()
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, mtuKey, fmt.Sprint(mtu))

	return nil
}

func (in *PTPInstaller) getDefaultMTU() int {
	mtu := in.defaultNIC.Link.MTU
	if mtu == 0 {
		dev := in.defaultNIC.Link.Name
		glog.Infof("Failed to read mtu from dev %s, set the default mtu to %d", dev, defaultMTU)
		mtu = defaultMTU
	}

	return mtu
}
