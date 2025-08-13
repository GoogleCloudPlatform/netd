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

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/golang/glog"
	"github.com/spf13/pflag"

	"github.com/GoogleCloudPlatform/netd/pkg/config"
	"github.com/GoogleCloudPlatform/netd/pkg/controllers/netconf"
	"github.com/GoogleCloudPlatform/netd/pkg/metrics"
	"github.com/GoogleCloudPlatform/netd/pkg/options"
	"github.com/GoogleCloudPlatform/netd/pkg/utils/clients"
	"github.com/GoogleCloudPlatform/netd/pkg/utils/nodeinfo"
	"github.com/GoogleCloudPlatform/netd/pkg/version"
)

func main() {
	netdConfig := options.NewNetdConfig()
	netdConfig.AddFlags(pflag.CommandLine)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	glog.Infof("netd version: %s", version.Version)
	pflag.CommandLine.VisitAll(func(f *pflag.Flag) {
		glog.Infof("FLAG: --%s=%q", f.Name, f.Value)
	})

	clientset, err := clients.NewClientSet()
	if err != nil {
		glog.Fatal(err)
	}
	nodeName, err := nodeinfo.GetNodeName()
	if err != nil {
		glog.Fatal(err)
	}

	if err := config.InitPolicyRouting(context.Background(), clientset, nodeName); err != nil {
		glog.Fatalf("Failed to create policy routing config set: %v", err)
	}

	nc := netconf.NewNetworkConfigController(netdConfig.EnablePolicyRouting, netdConfig.EnableSourceValidMark, netdConfig.ExcludeDNS, netdConfig.ReconcileInterval)

	stopCh := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)

	glog.Infof("Starting netd")
	go nc.Run(stopCh, &wg)

	if err := metrics.StartCollector(); err != nil {
		glog.Errorf("Could not start metrics collector: %v", err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	glog.Infof("Shutting down netd ...")
	close(stopCh)

	wg.Wait()
}
