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

package install

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
	"github.com/GoogleCloudPlatform/netd/internal/rest"
	"github.com/GoogleCloudPlatform/netd/internal/systemutil"
	"github.com/GoogleCloudPlatform/netd/pkg/install-cni/plugin"
	"github.com/GoogleCloudPlatform/netd/pkg/util"
)

// Config struct defines the CNI installation config options.
type Config struct {
	CNIConfigTemplate string
	CNIConfigName     string

	EnableCalicoNetworkPolicy   bool
	CalicoCNIConfigTemplateFile string
	CalicoCNIConfigTemplate     string

	EnableCiliumPlugin      bool
	EnableBandwidthPlugin   bool
	EnableMasquerade        bool
	EnablePrivateIPv6Access bool
}

type CNIInstaller struct {
	ctx context.Context

	// Configuration
	cfg        *Config
	cniConfDir string
	cniBinDir  string
	podCIDR    string
	defaultNIC systemutil.NIC

	// Interfaces for overriding in tests
	sysctlFunc systemutil.SysctlFunc
	client     rest.HTTPClient
	ipv4Tables ipt.IPTabler
	ipv6Tables ipt.IPTabler
}

func NewCNIInstaller(ctx context.Context, cfg *Config,
	cniConfDir, cniBinDir, podCIDR string, defaultNIC systemutil.NIC) *CNIInstaller {
	return &CNIInstaller{
		ctx:        ctx,
		cfg:        cfg,
		cniConfDir: cniConfDir,
		cniBinDir:  cniBinDir,
		podCIDR:    podCIDR,
		defaultNIC: defaultNIC,
		sysctlFunc: sysctl.Sysctl,
		client:     http.DefaultClient,
		ipv4Tables: ipt.IPv4Tables,
		ipv6Tables: ipt.IPv6Tables,
	}
}

// Run generates a CNI config file based on the configuration.
func (in *CNIInstaller) Run() error {
	if len(in.cfg.CNIConfigTemplate) == 0 {
		return fmt.Errorf("CNI config template is empty")
	}

	// Override calico network policy config if its CNI is not installed as expected
	// This is likely due to incomplete GKE configuration or restarting the node and disabling calico network policy
	// More info here: https://github.com/GoogleCloudPlatform/netd/issues/91
	glog.Infof("Calico network policy config: %v", in.cfg.EnableCalicoNetworkPolicy)
	if in.cfg.EnableCalicoNetworkPolicy {
		if exists, err := in.calicoCNIConfigFileExists(); err != nil {
			return err
		} else if !exists {
			// Timed out waiting for Calico CNI config file
			in.cfg.EnableCalicoNetworkPolicy = false
			glog.Infof("Update calico network policy config to %v", in.cfg.EnableCalicoNetworkPolicy)
		}
	}

	// Get CNI config template and output filepath
	var cniConfigTemplate, cniConfigFilepath string
	if in.cfg.EnableCalicoNetworkPolicy {
		glog.Info("Calico Network Policy is enabled.")
		if len(in.cfg.CalicoCNIConfigTemplateFile) == 0 {
			glog.Info("No Calico CNI spec template filepath specified. Exiting (0)...")
			return nil
		}
		if len(in.cfg.CalicoCNIConfigTemplate) == 0 {
			glog.Info("No Calico CNI spec template specified. Exiting (0)...")
			return nil
		}
		cniConfigTemplate = in.cfg.CalicoCNIConfigTemplate
		cniConfigFilepath = in.cfg.CalicoCNIConfigTemplateFile
	} else {
		cniConfigTemplate = in.cfg.CNIConfigTemplate
		cniConfigFilepath = filepath.Join(in.cniConfDir, in.cfg.CNIConfigName)
	}

	// Initialize and run installers
	pluginInstallers := []plugin.Installer{
		plugin.NewPTPInstaller(in.cniBinDir, in.podCIDR, in.defaultNIC, &cniConfigTemplate),
		plugin.NewPrivateIPv6AccessInstaller(in.cfg.EnablePrivateIPv6Access, in.cfg.EnableCalicoNetworkPolicy,
			in.sysctlFunc, in.client, in.ipv6Tables, &cniConfigTemplate),
		plugin.NewMasqueradeInstaller(in.cfg.EnableMasquerade, in.ipv4Tables),
		plugin.NewBandwidthInstaller(in.cfg.EnableBandwidthPlugin, in.cniBinDir, &cniConfigTemplate),
		plugin.NewCiliumInstaller(in.cfg.EnableCiliumPlugin, &cniConfigTemplate),
	}
	for _, in := range pluginInstallers {
		if err := in.Run(); err != nil {
			return err
		}
	}

	cniConfig := []byte(cniConfigTemplate)
	// Verify the generated CNI config file is a valid .conflist CNI config file
	if _, err := libcni.ConfListFromBytes(cniConfig); err != nil {
		return err
	}

	// Atomically write CNI config file
	if err := util.AtomicWrite(cniConfigFilepath, cniConfig, os.FileMode(0644)); err != nil {
		return err
	}

	return nil
}

// calicoCNIConfigFileExists watches the cniConfDir and blocks until a Calico CNI config file is found.
// This function will time out after 120 seconds if Calico CNI config file hasn't been found.
func (in *CNIInstaller) calicoCNIConfigFileExists() (bool, error) {
	watcher, fileModified, errChan, err := util.CreateFileWatcher(in.cniConfDir)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = watcher.Close()
	}()
	extensions := []string{".conflist"}
	for timeout := time.After(120 * time.Second); ; {
		if exists, err := validCNIConfigFileExists(in.cniConfDir, "calico", extensions); err != nil {
			return false, err
		} else if exists {
			// Found Calico CNI config file
			return true, nil
		}
		select {
		case <-fileModified:
		case err := <-errChan:
			return false, err
		case <-in.ctx.Done():
			return false, in.ctx.Err()
		case <-timeout:
			// Check one last time
			if exists, err := validCNIConfigFileExists(in.cniConfDir, "calico", extensions); err != nil {
				return false, err
			} else if exists {
				// Found Calico CNI config file
				return true, nil
			}
			// Timed out waiting for Calico CNI config file
			return false, nil
		}
	}
}

// validCNIConfigFileExist returns true if a valid CNI config file is found in confDir
// with a name that contains `substr` and an extension in `extensions`.
func validCNIConfigFileExists(confDir, substr string, extensions []string) (bool, error) {
	files, err := libcni.ConfFiles(confDir, extensions)
	switch {
	case err != nil:
		return false, err
	case len(files) == 0:
		return false, nil
	}

	sort.Strings(files)
	for _, confFile := range files {
		if !strings.Contains(filepath.Base(confFile), substr) {
			continue
		}

		if strings.HasSuffix(confFile, ".conflist") {
			// ConfListFromFile checks for a valid .conflist CNI config file
			_, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				// Error loading CNI config list file
				continue
			}
		}

		return true, nil
	}

	return false, nil
}
