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

package metrics

import (
	"flag"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/GoogleCloudPlatform/netd/pkg/metrics/collector"
)

var mcfg struct {
	enabledCollectors string
	listenAddress     string
	procPath          string
	stackType					string
}

func init() {
	flag.StringVar(&mcfg.enabledCollectors, "metrics-collectors", "",
		"Enable given metrics collectors (options: conntrack,socket,kernel_metrics,netlink_metrics,pod_ip_metrics).")
	flag.StringVar(&mcfg.listenAddress, "metrics-address", "localhost:10231", "Address on which to expose metrics.")
	flag.StringVar(&mcfg.procPath, "metrics-proc-path", "/proc", "Proc directory to read metrics.")
	flag.StringVar(&mcfg.stackType, "stack-type", "IPV4", "Stack type.")
}

// StartCollector starts the metrics collector with mcfg configured from input flag
func StartCollector() error {
	if mcfg.enabledCollectors == "" {
		glog.Infof("No metrics collectors were enabled.")
		return nil
	}
	enabledCollectors := strings.Split(mcfg.enabledCollectors, ",")
	nc, pc, err := collector.NewNodeCollector(enabledCollectors, mcfg.procPath, mcfg.stackType)
	if err != nil {
		return err
	}
	glog.Infof("Enabled metrics collectors:")
	for n := range nc.Collectors {
		glog.Infof(" - %s", n)
	}

	registry := prometheus.NewRegistry()
	err = registry.Register(nc)
	if err != nil {
		glog.Errorf("Couldn't register collector: %v", err)
		return err
	}

	for _, c := range pc {
		registry.MustRegister(c)
	}

	gatherers := prometheus.Gatherers{
		registry,
	}

	// Delegate http serving to Prometheus client library, which will call collector.Collect.
	h := promhttp.InstrumentMetricHandler(
		registry,
		promhttp.HandlerFor(gatherers,
			promhttp.HandlerOpts{
				ErrorHandling: promhttp.ContinueOnError,
			}),
	)

	go func() {
		http.HandleFunc("/metrics", h.ServeHTTP)
		glog.Infof("Listening on %s", mcfg.listenAddress)
		err = http.ListenAndServe(mcfg.listenAddress, nil)
		if err != nil {
			glog.Errorf("Couldn't start http server- %v", err)
		}
	}()
	return nil
}
