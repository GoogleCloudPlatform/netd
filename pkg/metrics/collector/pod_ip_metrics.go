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
	"math"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
)

type ipFamily int

const (
	ipv4 ipFamily = iota
	ipv6
	dual

	gkePodNetworkDir = "/host/var/lib/cni/networks/gke-pod-network"
	dualStack        = "IPV4_IPV6"

	// To configure the prometheus histogram bucket for ip reuse.
	bucketStart = 5e3
	bucketWidth = 5e3
	bucketCount = 12
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
	ipReuseMinDesc = prometheus.NewDesc(
		"ip_reuse_minimum_time_milliseconds",
		"Indicates the minimum IP reuse time.",
		nil, nil,
	)
	ipReuseAvgDesc = prometheus.NewDesc(
		"ip_reuse_average_time_milliseconds",
		"Indicates the average IP reuse time.",
		nil, nil,
	)
	// We want 60 seconds to be the threshold for watching quick ip reuse cases.
	// So the histogram will fill the 12 buckets until 60 seconds with size 5 seconds.
	// Others that are above 60 seconds will go to bucket {le="+Inf"}, which are out-of-concerned.
	bucketKeys           = prometheus.LinearBuckets(bucketStart, bucketWidth, bucketCount)
	ipReuseHistogramDesc = prometheus.NewDesc(
		"ip_reuse_time_duration_milliseconds",
		"Indicates the IP reuse duration in millisecond for all IPs.",
		nil, nil,
	)
	podIpMetricsWatcherSetup = false
)

type podIpMetricsCollector struct {
	usedIpv4AddrCount   uint64
	usedIpv6AddrCount   uint64
	dualStackCount      uint64
	dualStackErrorCount uint64
	duplicateIpCount    uint64
	reuseIps            reuseIps
	reuseMap            map[string]*ipReuse
	clock               clock
}

type reuseIps struct {
	count   uint64
	sum     float64
	min     uint64
	buckets map[float64]uint64
}

// IpReuse contains values for reuseMap tracking ip reuse status.
type ipReuse struct {
	ipReleasedTimestamp time.Time
	ipReuseInterval     float64
}

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (c *realClock) Now() time.Time {
	return time.Now()
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
	return &podIpMetricsCollector{clock: &realClock{}}, nil
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

func getIPv4(s string) (bool, string) {
	names := strings.Split(s, "/")
	f := names[len(names)-1]
	ip := net.ParseIP(f)
	if ip == nil || ip.To4() == nil {
		return false, ""
	}
	return true, f
}

// After the ip is removed, it will be put into the reuseMap.
// After the ip is reused, the reuseMap will update the ip reuse interval.
// The reuseMap will not record any ip that is being used unless it is reused.
func (c *podIpMetricsCollector) updateReuseIpStats(e fsnotify.Event, f string) {
	reuseIp, ok := c.reuseMap[f]
	switch {
	case e.Op&fsnotify.Remove == fsnotify.Remove:
		if !ok {
			c.reuseMap[f] = &ipReuse{c.clock.Now(), 0}
		} else {
			reuseIp.ipReleasedTimestamp = c.clock.Now()
		}
	case e.Op&fsnotify.Create == fsnotify.Create:
		if ok {
			oldT := reuseIp.ipReleasedTimestamp
			diff := uint64(c.clock.Now().Sub(oldT).Milliseconds())
			if diff > 0 {
				reuseIp.ipReuseInterval = float64(diff)
				c.reuseIps.count += 1
				c.reuseIps.sum += float64(diff)
				if diff < c.reuseIps.min {
					c.reuseIps.min = diff
				}
				c.fillBuckets(diff)
			}
		}
	}
}

func (c *podIpMetricsCollector) fillBuckets(diff uint64) {
	for _, bound := range bucketKeys {
		if float64(diff) < bound {
			c.reuseIps.buckets[bound]++
		}
	}
}

func (c *podIpMetricsCollector) setupDirectoryWatcher(dir string) error {
	if err := c.listIpAddresses(dir); err != nil {
		return err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		glog.Errorf("NewWatcher failed: %v", err)
		return err
	}

	c.reuseIps.min = uint64(math.Inf(+1))
	c.reuseIps.buckets = make(map[float64]uint64)
	for _, bound := range bucketKeys {
		c.reuseIps.buckets[bound] = 0
	}
	c.reuseMap = make(map[string]*ipReuse)

	go func() {
		defer func() {
			watcher.Close()
			podIpMetricsWatcherSetup = false
		}()

		for {
			select {
			case e, ok := <-watcher.Events:
				if !ok {
					glog.Error("watcher is not ok")
					return
				}
				if err := c.listIpAddresses(dir); err != nil {
					return
				}
				// Only update the ip reuse mininum, average and histogram for IPv4.
				ok, f := getIPv4(e.Name)
				if ok {
					c.updateReuseIpStats(e, f)
				}

			case err, ok := <-watcher.Errors:
				glog.Errorf("Received error from watcher %v, ok: %t", err, ok)
				if !ok {
					return
				}
			}
		}
	}()

	err = watcher.Add(dir)
	if err != nil {
		glog.Errorf("Failed to add watcher for directory %s: %v", dir, err)
	}
	podIpMetricsWatcherSetup = true
	return nil
}

func (c *podIpMetricsCollector) Update(ch chan<- prometheus.Metric) error {
	if !podIpMetricsWatcherSetup {
		if err := c.setupDirectoryWatcher(gkePodNetworkDir); err != nil {
			glog.Errorf("setupDirectoryWatcher returned error: %v", err)
			return nil
		}
	}
	ch <- prometheus.MustNewConstMetric(usedIpv4AddrCountDesc, prometheus.GaugeValue, float64(c.usedIpv4AddrCount))
	ch <- prometheus.MustNewConstMetric(usedIpv6AddrCountDesc, prometheus.GaugeValue, float64(c.usedIpv6AddrCount))
	ch <- prometheus.MustNewConstMetric(dualStackCountDesc, prometheus.GaugeValue, float64(c.dualStackCount))
	ch <- prometheus.MustNewConstMetric(dualStackErrorCountDesc, prometheus.GaugeValue, float64(c.dualStackErrorCount))
	ch <- prometheus.MustNewConstMetric(duplicateIpCountDesc, prometheus.GaugeValue, float64(c.duplicateIpCount))

	ch <- prometheus.MustNewConstMetric(ipReuseMinDesc, prometheus.GaugeValue, float64(c.reuseIps.min))
	ch <- prometheus.MustNewConstMetric(ipReuseAvgDesc, prometheus.GaugeValue, float64((c.reuseIps.sum / float64(c.reuseIps.count))))
	ch <- prometheus.MustNewConstHistogram(ipReuseHistogramDesc, c.reuseIps.count, c.reuseIps.sum, c.reuseIps.buckets)

	return nil
}
