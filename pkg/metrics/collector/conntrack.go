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
	conntrackEntriesDesc = prometheus.NewDesc(
		"conntrack_entries",
		"Number of currently allocated flow entries for connection tracking.",
		nil, nil,
	)
	conntrackErrorCountDesc = prometheus.NewDesc(
		"conntrack_error_count",
		"Conntrack counters.",
		[]string{"type"}, nil,
	)
	conntrackSizeDesc = prometheus.NewDesc(
		"conntrack_size",
		"Size of connection tracking table.",
		nil, nil,
	)
)

type conntrackCollector struct {
}

func init() {
	registerCollector("conntrack", NewConntrackCollector)
}

// NewConntrackCollector returns a new Collector exposing conntrack stats.
func NewConntrackCollector() (Collector, error) {
	return &conntrackCollector{}, nil
}

type conntrackStats struct {
	found         uint64
	invalid       uint64
	insert        uint64
	insertFailed  uint64
	drop          uint64
	earlyDrop     uint64
	searchRestart uint64
}

func (c *conntrackStats) merge(other *conntrackStats) {
	c.found += other.found
	c.invalid += other.invalid
	c.insert += other.insert
	c.insertFailed += other.insertFailed
	c.drop += other.drop
	c.earlyDrop += other.earlyDrop
	c.searchRestart += other.searchRestart

}

type conntrackIndices struct {
	numFields     int
	found         int
	invalid       int
	insert        int
	insertFailed  int
	drop          int
	earlyDrop     int
	searchRestart int
}

// parseHeader parses the conntrack header line, returning the
// indexes of the fields we wish to extract.
func parseHeader(line string) (*conntrackIndices, error) {
	indices := &conntrackIndices{
		found:         -1,
		invalid:       -1,
		insert:        -1,
		insertFailed:  -1,
		drop:          -1,
		earlyDrop:     -1,
		searchRestart: -1,
	}
	nameParts := strings.Split(line, " ")
	indices.numFields = len(nameParts)
	for i, v := range nameParts {
		switch v {
		case "found":
			indices.found = i
		case "invalid":
			indices.invalid = i
		case "insert":
			indices.insert = i
		case "insert_failed":
			indices.insertFailed = i
		case "drop":
			indices.drop = i
		case "early_drop":
			indices.earlyDrop = i
		case "search_restart":
			indices.searchRestart = i
		}
	}
	if indices.found == -1 || indices.invalid == -1 ||
		indices.insert == -1 || indices.insertFailed == -1 ||
		indices.drop == -1 || indices.earlyDrop == -1 ||
		indices.searchRestart == -1 {
		return nil, fmt.Errorf("invalid header %q: doesn't have target fields", line)
	}
	return indices, nil
}

// parseConntrackData parses a line of conntrack stat file
func parseConntrackData(line string, indices *conntrackIndices) (*conntrackStats, error) {
	stats := &conntrackStats{}
	valueParts := strings.Split(line, " ")
	if len(valueParts) != indices.numFields {
		return nil, fmt.Errorf("invalid input %q: doesn't have enough fields", line)
	}

	for _, e := range []struct {
		name  string
		value *uint64
		index int
	}{
		{"found", &stats.found, indices.found},
		{"invalid", &stats.invalid, indices.invalid},
		{"insert", &stats.insert, indices.insert},
		{"insert_failed", &stats.insertFailed, indices.insertFailed},
		{"drop", &stats.drop, indices.drop},
		{"early_drop", &stats.earlyDrop, indices.earlyDrop},
		{"search_restart", &stats.searchRestart, indices.searchRestart},
	} {
		v, err := strconv.ParseUint(valueParts[e.index], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("input does not have a valid %q field (line = %q)", e.name, line)
		}
		*e.value = v
	}

	return stats, nil
}

// parseConntrackFile parses the conntrack file contents read in from `r` and returns a merged set of stats.
func parseConntrackFile(r io.Reader) (*conntrackStats, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return nil, fmt.Errorf("empty file")
	}
	indices, err := parseHeader(scanner.Text())
	if err != nil {
		return nil, err
	}

	var lineCount int
	accStats := &conntrackStats{}
	for scanner.Scan() {
		lineCount++
		stats, err := parseConntrackData(scanner.Text(), indices)
		if err != nil {
			return nil, err
		}
		accStats.merge(stats)
	}
	if lineCount == 0 {
		return nil, fmt.Errorf("missing data")
	}
	return accStats, nil
}

func getConntrackStats(fileName string) (*conntrackStats, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseConntrackFile(file)
}

func (c *conntrackCollector) Update(ch chan<- prometheus.Metric) error {
	value, err := readUintFromFile(procFilePath("sys/net/netfilter/nf_conntrack_count"))
	if err != nil {
		return nil
	}
	ch <- prometheus.MustNewConstMetric(conntrackEntriesDesc, prometheus.GaugeValue, float64(value))

	size, err := readUintFromFile(procFilePath("sys/net/netfilter/nf_conntrack_max"))
	if err != nil {
		return nil
	}
	ch <- prometheus.MustNewConstMetric(conntrackSizeDesc, prometheus.GaugeValue, float64(size))

	stats, err := getConntrackStats(procFilePath("net/stat/nf_conntrack"))
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.found), "found")
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.invalid), "invalid")
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.insert), "insert")
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.insertFailed), "insert_failed")
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.drop), "drop")
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.earlyDrop), "early_drop")
	ch <- prometheus.MustNewConstMetric(conntrackErrorCountDesc, prometheus.CounterValue, float64(stats.searchRestart), "search_restart")
	return nil
}
