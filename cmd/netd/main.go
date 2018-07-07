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
	"sync"
	"syscall"

	"github.com/GoogleCloudPlatform/netd/pkg/controllers/netconf"
	"github.com/GoogleCloudPlatform/netd/pkg/options"
	"github.com/golang/glog"
	"github.com/spf13/pflag"
)

func main() {
	config := options.NewNetdConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	glog.Infof("Starting netd ...")
	defer glog.Infof("Shutting down netd ...")

	nc := netconf.NewNetworkConfigController(config.EnablePolicyRouting, config.EnableMasquerade)

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	wg.Add(1)
	go nc.Run(stopCh, &wg)

	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	close(stopCh)

	wg.Wait()
}
