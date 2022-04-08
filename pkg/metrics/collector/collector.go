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

// This package is modified from prometheus node_exporter

package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	scrapeFailureCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scrape_collector_fail",
		Help: "scrape collector fail count.",
	}, []string{"collector"})

	scrapeDurationHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "scrape_collector_durations_histogram_seconds",
		Help:    "scrape duration distributions.",
		Buckets: prometheus.ExponentialBuckets(0.00001, 10, 8),
	}, []string{"collector"})

	// Needed by prometheus-to-sd. Since we didn't use the default registry,
	// we manually provide this stat here.
	processStartDesc = prometheus.NewDesc(
		"process_start_time_seconds",
		"Start time of the process since unix epoch in seconds.",
		nil,
		nil,
	)

	// factories is a collection of all supported collectors
	factories = make(map[string]func() (Collector, error))
)

// registerCollector registers a collector with the input func being the creator of the collector
func registerCollector(collector string, factory func() (Collector, error)) {
	factories[collector] = factory
}

// NodeCollector implements the prometheus.Collector interface.
type NodeCollector struct {
	Collectors map[string]Collector
	startTime  int64
}

// NewNodeCollector creates a new NodeCollector with given enabledCollectors (a list
// of enabled collectors name) and a list of prometheus collector
func NewNodeCollector(enabledCollectors []string, proc string, stack string) (*NodeCollector, []prometheus.Collector, error) {
	procPath = proc
	stackType = stack
	collectors := make(map[string]Collector)
	for _, name := range enabledCollectors {
		createFunc, exist := factories[name]
		if !exist {
			return nil, nil, fmt.Errorf("missing collector: %q", name)
		}
		if c, err := createFunc(); err == nil {
			collectors[name] = c
		} else {
			return nil, nil, err
		}
	}
	return &NodeCollector{Collectors: collectors, startTime: time.Now().Unix()},
		[]prometheus.Collector{scrapeDurationHist, scrapeFailureCount},
		nil
}

// Describe implements the prometheus.Collector interface.
func (n *NodeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- processStartDesc
}

// Collect implements the prometheus.Collector interface.
func (n *NodeCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(processStartDesc, prometheus.GaugeValue, float64(n.startTime))

	wg := sync.WaitGroup{}
	wg.Add(len(n.Collectors))
	for name, c := range n.Collectors {
		go func(name string, c Collector) {
			execute(name, c, ch)
			wg.Done()
		}(name, c)
	}
	wg.Wait()
}

func execute(name string, c Collector, ch chan<- prometheus.Metric) {
	begin := time.Now()
	err := c.Update(ch)
	duration := time.Since(begin)

	scrapeDurationHist.WithLabelValues(name).Observe(duration.Seconds())
	if err != nil {
		glog.Errorf("Collector %q failed (took %v) %v", name, duration, err)
		scrapeFailureCount.WithLabelValues(name).Inc()
	}
}

// Collector is the interface a collector has to implement.
type Collector interface {
	// Update gets new metrics and expose them via prometheus registry.
	Update(ch chan<- prometheus.Metric) error
}
