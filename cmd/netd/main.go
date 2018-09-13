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
	"flag"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/GoogleCloudPlatform/netd/pkg/controllers/netconf"
	"github.com/GoogleCloudPlatform/netd/pkg/options"
	"github.com/GoogleCloudPlatform/netd/pkg/version"
	"github.com/golang/glog"
	"github.com/spf13/pflag"
)

func main() {
	config := options.NewNetdConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	glog.Infof("netd version: %v", version.VERSION)
	glog.Infof("netd args: %v", strings.Join(os.Args, " "))

	nc := netconf.NewNetworkConfigController(config.EnablePolicyRouting, config.EnableMasquerade,
		config.ReconcileIntervalSeconds)
	nc.PrintConfig()

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	wg.Add(1)
	go nc.Run(stopCh, &wg)
	glog.Infof("netd started")

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	glog.Infof("Shutting down netd ...")
	close(stopCh)

	wg.Wait()
}
