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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
	"github.com/GoogleCloudPlatform/netd/internal/rest"
	"github.com/GoogleCloudPlatform/netd/internal/systemutil"
)

const (
	ipv6SubnetKey      = "@ipv6SubnetOptional"
	ipv6SubnetTemplate = `,
          [
            {
              "subnet": "%v/112"
            }
          ]`
	ipv6RouteKey      = "@ipv6RouteOptional"
	ipv6RouteTemplate = `,
          {
            "dst": "::/0"
          }`
)

const (
	tableFilter      = "filter"
	forwardChainName = "FORWARD"
	inputChainName   = "INPUT"
	outputChainName  = "OUTPUT"
)

const (
	instanceMetadataURL  = "http://metadata.google.internal/computeMetadata/v1/instance"
	sysctlIPv6Forwarding = "net.ipv6.conf.all.forwarding"
)

var errNoIPv6AddrFound = errors.New("no IPv6 address found for nic0")

type PrivateIPv6AccessInstaller struct {
	enabled                   bool
	enableCalicoNetworkPolicy bool
	sysctlFunc                systemutil.SysctlFunc
	client                    rest.HTTPClient
	ipv6Tables                ipt.IPTabler
	cniConfigTemplate         *string
}

func NewPrivateIPv6AccessInstaller(enabled, enableCalicoNetworkPolicy bool,
	sysctlFunc systemutil.SysctlFunc, client rest.HTTPClient, ipv6Tables ipt.IPTabler, cniConfigTemplate *string) *PrivateIPv6AccessInstaller {
	return &PrivateIPv6AccessInstaller{
		enabled:                   enabled,
		enableCalicoNetworkPolicy: enableCalicoNetworkPolicy,
		sysctlFunc:                sysctlFunc,
		client:                    client,
		ipv6Tables:                ipv6Tables,
		cniConfigTemplate:         cniConfigTemplate,
	}
}

func (in *PrivateIPv6AccessInstaller) Run() error {
	if !in.enabled {
		in.clearIPv6Fields("private IPv6 access is disabled")
		return nil
	}

	nodeIPv6Addr, err := in.getNodeIPv6Addr()
	if err != nil {
		if errors.Is(err, errNoIPv6AddrFound) {
			in.clearIPv6Fields(err.Error())
			return nil
		}
		return err
	}

	glog.Infof("Found nic0 IPv6 address %v. Filling IPv6 subnet and route...", nodeIPv6Addr)
	ipv6Subnet := fmt.Sprintf(ipv6SubnetTemplate, nodeIPv6Addr)
	ipv6Route := ipv6RouteTemplate
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, ipv6SubnetKey, ipv6Subnet)
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, ipv6RouteKey, ipv6Route)

	if err := in.installIPv6TablesRules(); err != nil {
		return err
	}

	if in.enableCalicoNetworkPolicy {
		glog.Info("Enabling IPv6 forwarding...")
		_, err := in.sysctlFunc(sysctlIPv6Forwarding, "1")
		if err != nil {
			return err
		}
	}

	return nil
}

func (in *PrivateIPv6AccessInstaller) getNodeIPv6Addr() (string, error) {
	url := instanceMetadataURL + "/network-interfaces/0/?recursive=true"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	res, err := in.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resBody, &data); err != nil {
		return "", fmt.Errorf("%w: %v", errNoIPv6AddrFound, err.Error())
	}
	ipv6s, ok := data["ipv6s"].([]interface{})
	if !ok {
		return "", errNoIPv6AddrFound
	}
	nodeIPv6Addr, ok := ipv6s[0].(string)
	if !ok {
		return "", errNoIPv6AddrFound
	}

	return nodeIPv6Addr, nil
}

func (in *PrivateIPv6AccessInstaller) installIPv6TablesRules() error {
	// Ensure the IPv6 firewall rules are as expected.
	// These rules mirror the IPv4 rules installed by kubernetes/cluster/gce/gci/configure-helper.sh
	rules, err := in.ipv6Tables.List(tableFilter, forwardChainName)
	if err != nil {
		return err
	}
	// Get the default chain policy at rules[0]
	if len(rules) > 0 && strings.Contains(rules[0], fmt.Sprintf("-P %v DROP", forwardChainName)) {
		glog.Info("Add rules to accept all forwarded TCP/UDP/ICMP/SCTP IPv6 packets")
		ruleSpecs := []ipt.IPTablesSpec{
			{
				TableName: tableFilter,
				ChainName: forwardChainName,
				Rules: []ipt.IPTablesRule{
					{"-p", "tcp", "-j", "ACCEPT"},
					{"-p", "udp", "-j", "ACCEPT"},
					{"-p", "icmpv6", "-j", "ACCEPT"},
					{"-p", "sctp", "-j", "ACCEPT"},
				},
				IPT: in.ipv6Tables,
			},
		}
		for _, s := range ruleSpecs {
			for _, r := range s.Rules {
				if err := s.IPT.AppendUnique(s.TableName, s.ChainName, r...); err != nil {
					return err
				}
			}
		}
	}

	// Ensure the other IPv6 rules we need are also installed before any other node rules.
	ruleSpecs := []ipt.IPTablesSpec{
		{
			TableName: tableFilter,
			ChainName: inputChainName,
			Rules: []ipt.IPTablesRule{
				// Always allow ICMP
				{"-p", "icmpv6", "-j", "ACCEPT"},
				// Note that this expects dhclient to actually obtain and assign an IPv6 address to eth0.
				{"-p", "udp", "-m", "udp", "--dport", "546", "-j", "ACCEPT"},
				// Accept return traffic inbound
				{"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			},
			IPT: in.ipv6Tables,
		},
		{
			TableName: tableFilter,
			ChainName: outputChainName,
			Rules: []ipt.IPTablesRule{
				// Always allow ICMP
				{"-p", "icmpv6", "-j", "ACCEPT"},
				// Accept new and return traffic outbound
				{"-m", "state", "--state", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"},
			},
			IPT: in.ipv6Tables,
		},
	}

	for _, s := range ruleSpecs {
		for _, r := range s.Rules {
			// Insert at head of chain (rule position 1)
			if err := s.IPT.Insert(s.TableName, s.ChainName, 1, r...); err != nil {
				return err
			}
		}
	}

	return nil
}

func (in *PrivateIPv6AccessInstaller) clearIPv6Fields(msg string) {
	glog.Infof("Clearing IPv6 subnet and route: %s", msg)
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, ipv6SubnetKey, "")
	*in.cniConfigTemplate = strings.ReplaceAll(*in.cniConfigTemplate, ipv6RouteKey, "")
}
