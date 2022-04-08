/*
Copyright 2022 Google Inc.

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
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
)

type ipFamily int

const (
	gkePodNetworkDir = "/host/var/lib/cni/networks/gke-pod-network"
	ipv4 ipFamily = iota
	ipv6 = 1
	dual = 2
	dualStack = "IPV4_IPV6"
)

var (
	usedIpv4AddrCountDesc = prometheus.NewDesc(
		"used_ipv4_addr_count",
		"Indicates how many IPv4 addresses are in use.",
		nil, nil,
	)
	usedIpv6AddrCountDesc = prometheus.NewDesc(
		"used_ipv6_addr_count",
		"Indicates how many IPv6 addresses are in use.",
		nil, nil,
	)
	dualStackCountDesc = prometheus.NewDesc(
		"dual_stack_count",
		"Indicates how many pods have dual stack IP addresses.",
		nil, nil,
	)
	dualStackErrorCountDesc = prometheus.NewDesc(
		"dual_stack_error_count",
		"Indicates how many pods did not get dual stack IPs erroneously.",
		nil, nil,
	)
	duplicateIpCountDesc = prometheus.NewDesc(
		"duplicate_ip_count",
		"Indicates how many pods had more than one IP per family.",
		nil, nil,
	)
)

type podIpMetricsCollector struct {
	usedIpv4AddrCount uint64
	usedIpv6AddrCount uint64
	dualStackCount uint64
	dualStackErrorCount uint64
	duplicateIpCount uint64
}

func (ip ipFamily) String() string {
	return [...]string{"IPV4", "IPV6", "IPV4_IPV6"}[ip]
}

func init() {
	registerCollector("pod_ip_metrics", NewPodIpMetricsCollector)
}

// NewPodIpMetricsCollector returns a new Collector exposing pod IP allocation
// stats.
func NewPodIpMetricsCollector() (Collector, error) {
	return &podIpMetricsCollector{}, nil
}

func readLine(path string) (string, error) {
	buf, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer func() {
		if err = buf.Close(); err != nil {
			glog.Errorf("Error closing file %s: %s", path, err)
		}
	}()

	s := bufio.NewScanner(buf)
	s.Scan()
	return s.Text(), s.Err()
}

func (c *podIpMetricsCollector) listIpAddresses(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		glog.Errorf("Error opening directory %s, %v", dir, err)
		return err
	}
	files, err := f.Readdir(0)
	if err != nil {
		glog.Errorf("Error while reading files in directory %v", err)
		return err
	}

	podMap := make(map[string]ipFamily)
	var ipv4Count, ipv6Count, dupIpCount, dualCount, dualErrCount uint64
	for _, v := range files {
		if ip := net.ParseIP(v.Name()); ip == nil {
			// This isn't an IP address file
			continue
		}
		var family ipFamily
		if strings.Contains(v.Name(), ":") {
			ipv6Count++
			family = ipv6
		} else {
			ipv4Count++
			family = ipv4
		}
		// Update the map and track IP families only for dual stack clusters
		fileName := fmt.Sprintf("%s/%s", dir, v.Name())
		podId, err := readLine(fileName)
		if err != nil {
			glog.Errorf("Error reading file %s: %v", fileName, err)
			continue
		}
		f, ok := podMap[podId]
		if !ok {
			podMap[podId] = family
		} else if (f == ipv4 && family == ipv6) || (f == ipv6 && family == ipv4) {
			podMap[podId] = dual
		} else {
			dupIpCount++
		}
	}
	if stackType == dualStack {
		for _, family := range podMap {
			if family == dual {
				dualCount++
			} else {
				dualErrCount++
			}
		}
	}
	c.usedIpv4AddrCount = ipv4Count
	c.usedIpv6AddrCount = ipv6Count
	c.dualStackCount = dualCount
	c.dualStackErrorCount = dualErrCount
	c.duplicateIpCount = dupIpCount
	return nil
}

func (c *podIpMetricsCollector) Update(ch chan<- prometheus.Metric) error {
	if err := c.listIpAddresses(gkePodNetworkDir); err != nil {
		glog.Errorf("ListIpAddresses returned error: %v", err)
		return nil
	}
	ch <- prometheus.MustNewConstMetric(usedIpv4AddrCountDesc, prometheus.GaugeValue, float64(c.usedIpv4AddrCount))
	ch <- prometheus.MustNewConstMetric(usedIpv6AddrCountDesc, prometheus.GaugeValue, float64(c.usedIpv6AddrCount))
	ch <- prometheus.MustNewConstMetric(dualStackCountDesc, prometheus.GaugeValue, float64(c.dualStackCount))
	ch <- prometheus.MustNewConstMetric(dualStackErrorCountDesc, prometheus.GaugeValue, float64(c.dualStackErrorCount))
	ch <- prometheus.MustNewConstMetric(duplicateIpCountDesc, prometheus.GaugeValue, float64(c.duplicateIpCount))

	return nil
}
