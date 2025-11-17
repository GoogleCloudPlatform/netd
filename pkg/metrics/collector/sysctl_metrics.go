/*
Copyright 2025 Google Inc.

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

package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultProcSysNetIpv4IpLocalPortRangeFileLocation = "/proc/sys/net/ipv4/ip_local_port_range"
)

var (
	ipLocalPortRangeDesc = prometheus.NewDesc(
		"sysctl_net_ipv4_ip_local_port_range",
		"The min and max values of net.ipv4.ip_local_port_range sysctl. Expected default is (32768, 60999).",
		[]string{"boundary"}, nil,
	)
)

type sysctlCollector struct {
	ipLocalPortRangeFileLocation string
}

func init() {
	registerCollector("sysctl_metrics", NewSysctlCollector)
}

func NewSysctlCollector() (Collector, error) {
	return &sysctlCollector{
		ipLocalPortRangeFileLocation: defaultProcSysNetIpv4IpLocalPortRangeFileLocation,
	}, nil
}

func parseIPLocalPortRange(content string) (min, max uint64, err error) {
	parts := strings.Fields(strings.TrimSpace(content))
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid ip_local_port_range format: expected 2 values, got %d. Content: %q", len(parts), content)
	}

	min, err = strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse min port value: %v", err)
	}

	max, err = strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse max port value: %v", err)
	}

	return min, max, nil
}

func (c *sysctlCollector) Update(ch chan<- prometheus.Metric) error {
	data, err := os.ReadFile(c.ipLocalPortRangeFileLocation)
	if err != nil {
		return fmt.Errorf("failed to read ip_local_port_range from %s: %v", c.ipLocalPortRangeFileLocation, err)
	}

	min, max, err := parseIPLocalPortRange(string(data))
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(ipLocalPortRangeDesc, prometheus.GaugeValue, float64(min), "min")
	ch <- prometheus.MustNewConstMetric(ipLocalPortRangeDesc, prometheus.GaugeValue, float64(max), "max")

	return nil
}
