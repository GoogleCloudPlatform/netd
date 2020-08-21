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
	"path/filepath"
	"strings"

	"github.com/coreos/etcd/pkg/fileutil"
	"github.com/golang/glog"
)

const (
	bandwidthPluginKey      = "@cniBandwidthPlugin"
	bandwidthPluginTemplate = `,
    {
      "type": "bandwidth",
      "capabilities": {
        "bandwidth": true
      }
    }`
)

const (
	bandwidthBinName = "bandwidth"
)

type BandwidthInstaller struct {
	enabled           bool
	cniBinDir         string
	cniConfigTemplate *string
}

func NewBandwidthInstaller(enabled bool, cniBinDir string, cniConfigFileTemplate *string) *BandwidthInstaller {
	return &BandwidthInstaller{
		enabled:           enabled,
		cniBinDir:         cniBinDir,
		cniConfigTemplate: cniConfigFileTemplate,
	}
}

func (in *BandwidthInstaller) Run() error {
	var bandwidthPluginConfig string
	if in.enabled {
		if bandwidthBinPath := filepath.Join(in.cniBinDir, bandwidthBinName); fileutil.Exist(bandwidthBinPath) {
			bandwidthPluginConfig = bandwidthPluginTemplate
		} else {
			glog.Warningf("Bandwidth plugin is enabled, but %s does not exist.", bandwidthBinPath)
		}
	}

	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, bandwidthPluginKey, bandwidthPluginConfig)

	return nil
}
