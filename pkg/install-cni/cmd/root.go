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

package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/GoogleCloudPlatform/netd/internal/systemutil"
	"github.com/GoogleCloudPlatform/netd/pkg/install-cni/install"
)

var rootCmd = &cobra.Command{
	Use:   "install-cni",
	Short: "Install and configure CNI plugin(s) on a node",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx := cmd.Context()

		cfg := constructConfig()

		var nodeName string
		nodeName, err = os.Hostname()
		if err != nil {
			return
		}

		// Get IPv4 subnet (PodCIDR)
		var node *v1.Node
		node, err = systemutil.GetNodeSpec(ctx, nodeName)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Error was caused by interrupt/termination signal
				err = nil
			}
			return
		}
		glog.Infof("PodCIDR validation succeeded: %s", node.Spec.PodCIDR)

		var defaultNIC *systemutil.NIC
		defaultNIC, err = systemutil.GetNIC(net.IPv4(8, 8, 8, 8))
		if err != nil {
			return
		}

		cniInstaller := install.NewCNIInstaller(ctx, cfg, CNIConfDir, CNIBinDir, node.Spec.PodCIDR, *defaultNIC)

		if err = cniInstaller.Run(); err != nil {
			if errors.Is(err, context.Canceled) {
				// Error was caused by interrupt/termination signal
				err = nil
			}
		}

		return
	},
}

// GetCommand returns the main cobra.Command object for this application
func GetCommand() *cobra.Command {
	return rootCmd
}

const (
	CNIBinDir  = "/host/home/kubernetes/bin"
	CNIConfDir = "/host/etc/cni/net.d"
)

const (
	CNIConfigTemplate           = "cni-spec-template"
	CNIConfigName               = "cni-spec-name"
	EnableCalicoNetworkPolicy   = "enable-calico-network-policy"
	CalicoCNIConfigTemplateFile = "calico-cni-spec-template-file"
	CalicoCNIConfigTemplate     = "calico-cni-spec-template"
	EnableCiliumPlugin          = "enable-cilium-plugin"
	EnableBandwidthPlugin       = "enable-bandwidth-plugin"
	EnableMasquerade            = "enable-masquerade"
	EnablePrivateIPv6Access     = "enable-private-ipv6-access"
)

func init() {
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	registerStringParameter(CNIConfigTemplate, "", "CNI configuration template as a string")
	registerStringParameter(CNIConfigName, "10-gke-ptp.conflist", "Name of CNI configuration file")

	registerBooleanParameter(EnableCalicoNetworkPolicy, false, "Whether to enable Calico network policy")
	registerStringParameter(CalicoCNIConfigTemplateFile, "", "Calico CNI configuration template as a file")
	registerStringParameter(CalicoCNIConfigTemplate, "", "Calico CNI configuration template as a string")

	registerBooleanParameter(EnableCiliumPlugin, true, "Whether to enable the Cilium plugin")
	registerBooleanParameter(EnableBandwidthPlugin, true, "Whether to enable the bandwidth plugin")
	registerBooleanParameter(EnableMasquerade, true, "Whether to enable IP masquerade")
	registerBooleanParameter(EnablePrivateIPv6Access, false, "Whether to enable private IPv6 access")
}

func registerStringParameter(name, value, usage string) {
	rootCmd.Flags().String(name, value, usage)
	bindViper(name)
}

func registerBooleanParameter(name string, value bool, usage string) {
	rootCmd.Flags().Bool(name, value, usage)
	bindViper(name)
}

func bindViper(name string) {
	if err := viper.BindPFlag(name, rootCmd.Flags().Lookup(name)); err != nil {
		glog.Error(err)
		os.Exit(1)
	}
}

func constructConfig() *install.Config {
	cfg := &install.Config{
		CNIConfigTemplate: viper.GetString(CNIConfigTemplate),
		CNIConfigName:     viper.GetString(CNIConfigName),

		EnableCalicoNetworkPolicy:   viper.GetBool(EnableCalicoNetworkPolicy),
		CalicoCNIConfigTemplateFile: viper.GetString(CalicoCNIConfigTemplateFile),
		CalicoCNIConfigTemplate:     viper.GetString(CalicoCNIConfigTemplate),

		EnableCiliumPlugin:      viper.GetBool(EnableCiliumPlugin),
		EnableBandwidthPlugin:   viper.GetBool(EnableBandwidthPlugin),
		EnableMasquerade:        viper.GetBool(EnableMasquerade),
		EnablePrivateIPv6Access: viper.GetBool(EnablePrivateIPv6Access),
	}

	return cfg
}
