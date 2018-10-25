/*
Copyright 2018 Google Inc.

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
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	socketInUseDesc = prometheus.NewDesc(
		"num_inuse_sockets",
		"Number of inuse sockets",
		[]string{"protocol"}, nil,
	)
	socketTimeWaitDesc = prometheus.NewDesc(
		"num_tw_sockets",
		"Number of sockets in time wait state",
		nil, nil,
	)
	socketMemoryDesc = prometheus.NewDesc(
		"socket_memory",
		"Amount of memory used by sockets",
		nil, nil,
	)
)

type sockStatCollector struct {
}

var pageSize = os.Getpagesize()

func init() {
	registerCollector("socket", NewSockStatCollector)
}

// NewSockStatCollector returns a new Collector exposing socket stats.
func NewSockStatCollector() (Collector, error) {
	return &sockStatCollector{}, nil
}

type socketStats struct {
	tcpInUse       uint64 // num of tcp in use sockets
	udpInUse       uint64 // num of udp in use sockets
	tcpTimeWait    uint64 // num of tcp timewait sockets
	memUsedInPages uint64 // sum of tcp and udp memory used in pages
}

func (s *socketStats) merge(o *socketStats) {
	s.tcpInUse += o.tcpInUse
	s.udpInUse += o.udpInUse
	s.tcpTimeWait += o.tcpTimeWait
	s.memUsedInPages += o.memUsedInPages
}

func getSockStats(fileName string) (*socketStats, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseSockStats(file)
}

func extractSockStatUint(field string, s string, out interface{}) error {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid value %q for field %q in sockstats", s, field)
	}
	outValue := out.(*uint64)
	*outValue = v
	return nil
}

type sockStatEntry struct {
	out     interface{}
	extract func(string, string, interface{}) error
}

func extractSockStatFields(fields []string, entries map[string]*sockStatEntry) error {
	for i := 0; i < len(fields) && i+1 < len(fields); i += 2 {
		k, v := fields[i], fields[i+1]
		e, ok := entries[k]
		if !ok {
			continue
		}
		if err := e.extract(k, v, e.out); err != nil {
			return err
		}
	}
	return nil
}

func parseLine(in string) (*socketStats, error) {
	line := strings.Split(in, " ")
	if len(line) < 2 || len(line[0]) < 2 || line[0][len(line[0])-1] != ':' {
		return nil, fmt.Errorf("invalid line %q", in)
	}

	ret := &socketStats{}
	tcpEntries := map[string]*sockStatEntry{
		"inuse": {&ret.tcpInUse, extractSockStatUint},
		"tw":    {&ret.tcpTimeWait, extractSockStatUint},
		"mem":   {&ret.memUsedInPages, extractSockStatUint},
	}

	udpEntries := map[string]*sockStatEntry{
		"inuse": {&ret.udpInUse, extractSockStatUint},
		"mem":   {&ret.memUsedInPages, extractSockStatUint},
	}

	protocol := line[0][:len(line[0])-1]
	rest := line[1:]

	switch protocol {
	case "TCP", "TCP6":
		if err := extractSockStatFields(rest, tcpEntries); err != nil {
			return nil, err
		}
	case "UDP", "UDP6":
		if err := extractSockStatFields(rest, udpEntries); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func parseSockStats(r io.Reader) (*socketStats, error) {
	var lineCount int

	scanner := bufio.NewScanner(r)
	ret := &socketStats{}
	for scanner.Scan() {
		lineCount++
		if s, err := parseLine(scanner.Text()); err == nil {
			ret.merge(s)
		} else {
			return nil, err
		}
	}
	if lineCount == 0 {
		return nil, fmt.Errorf("empty file")
	}
	return ret, nil
}

func (c *sockStatCollector) Update(ch chan<- prometheus.Metric) error {
	ss, err := getSockStats(procFilePath("net/sockstat"))
	if err != nil {
		return err
	}

	ss6, err := getSockStats(procFilePath("net/sockstat6"))
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(socketInUseDesc, prometheus.GaugeValue, float64(ss.tcpInUse+ss6.tcpInUse), "tcp")
	ch <- prometheus.MustNewConstMetric(socketInUseDesc, prometheus.GaugeValue, float64(ss.udpInUse+ss6.udpInUse), "udp")
	// sockstat6 file doesn't have tcp tw stats
	ch <- prometheus.MustNewConstMetric(socketTimeWaitDesc, prometheus.GaugeValue, float64(ss.tcpTimeWait))
	// sockstat6 file doesn't have mem stats
	ch <- prometheus.MustNewConstMetric(socketMemoryDesc, prometheus.GaugeValue, float64(ss.memUsedInPages*uint64(pageSize)))
	return nil
}
