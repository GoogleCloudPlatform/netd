/*
Copyright 2021 Google Inc.

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
	netstatLabel = "TcpExt:" // Label we use to parse netstat tcp metrics
	snmpLabel    = "Tcp:"    // Label we use to parse snmp tcp metrics
)

// Keys for metrics after parsing
const (
	// Got from Snmp counters
	tcpSegsIn      = "InSegs"      // Total tcp segments in
	tcpSegsOut     = "OutSegs"     // Total tcp segments out
	tcpSegsRetrans = "RetransSegs" // Total tcp segments retransmitted
	// Got from netstat
	tcpTimeoutRehash   = "TcpTimeoutRehash"      // Total tcp timeout rehash
	tcpDuplicateRehash = "TcpDupliateDataRehash" // Total tcp duplicates rehashed
)

var (
	tcpTimeoutDesc = prometheus.NewDesc(
		"tcp_timeout_rehash_count",
		"Tcp timeout rehash count",
		nil, nil,
	)
	tcpDuplicateDesc = prometheus.NewDesc(
		"tcp_duplicate_rehash_count",
		"Tcp duplicate rehash counts",
		nil, nil,
	)
	segmentsReceivedDesc = prometheus.NewDesc(
		"tcp_segments_received_count",
		"TCP segments received on the node",
		nil, nil,
	)
	segmentsSentDesc = prometheus.NewDesc(
		"tcp_segments_sent_count",
		"TCP segments sent from node",
		nil, nil,
	)
	segmentsRetransmittedDesc = prometheus.NewDesc(
		"tcp_segments_retransmitted_count",
		"TCP segments retransmitted on the node",
		nil, nil,
	)
)

type kernelStatCollector struct {
}

func init() {
	registerCollector("kernel_metrics", NewKernelStatCollector)
}

func NewKernelStatCollector() (Collector, error) {
	return &kernelStatCollector{}, nil
}

// Parses a string which contains two lines, each starting with label
// returning a map where the keys are the first lines elements, while the
// second line contains the values, all casted to uint64, e.g
//
// label key1 key2 key3
// label 1 2 3
//
// Outputs: {"key1":1 "key2":2 "key3":3}
func parseKeyValueLines(output, label string) (map[string]uint64, error) {
	stats := make(map[string]uint64)
	splitFile := strings.Split(output, "\n")
	for i, stat := range splitFile {
		if !strings.Contains(stat, label) {
			continue
		}
		keyList := strings.Fields(stat)
		// TODO(#112): Look for next instance of label rather than assuming its the next
		valList := strings.Fields(splitFile[i+1])
		if len(valList) != len(keyList) {
			// Return nothing if malformed.
			return nil, fmt.Errorf("malformed key value pair while parsing %q", label)
		}
		for i, key := range keyList[1:] {
			val, err := strconv.Atoi(valList[i+1])
			if err != nil {
				return nil, fmt.Errorf("could not cast value to uint64, got %q", err)
			}
			stats[key] = uint64(val)
		}
		return stats, nil
	}
	return stats, nil
}

func (c *kernelStatCollector) Update(ch chan<- prometheus.Metric) error {
	// Get snmp values.
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return fmt.Errorf("could not read proc/net/snmp")
	}
	output := string(data)
	netstats, err := parseKeyValueLines(output, snmpLabel)
	if err != nil {
		return err
	}
	if val, ok := netstats[tcpSegsIn]; ok {
		ch <- prometheus.MustNewConstMetric(segmentsReceivedDesc, prometheus.CounterValue, float64(val))
	}
	if val, ok := netstats[tcpSegsOut]; ok {
		ch <- prometheus.MustNewConstMetric(segmentsSentDesc, prometheus.CounterValue, float64(val))
	}
	if val, ok := netstats[tcpSegsRetrans]; ok {
		ch <- prometheus.MustNewConstMetric(segmentsRetransmittedDesc, prometheus.CounterValue, float64(val))
	}

	// Get netstat values
	data, err = os.ReadFile("/proc/net/netstat")
	if err != nil {
		return fmt.Errorf("could not read proc/net/netstat")
	}
	output = string(data)
	nstats, err := parseKeyValueLines(output, netstatLabel)
	if err != nil {
		return err
	}
	if val, ok := nstats[tcpTimeoutRehash]; ok {
		ch <- prometheus.MustNewConstMetric(tcpTimeoutDesc, prometheus.CounterValue, float64(val))
	}
	if val, ok := nstats[tcpDuplicateRehash]; ok {
		ch <- prometheus.MustNewConstMetric(tcpDuplicateDesc, prometheus.CounterValue, float64(val))
	}
	return nil
}
