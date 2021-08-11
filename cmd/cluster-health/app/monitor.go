/*
Copyright 2020 Google Inc.

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

package app

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type monitorOptions struct {
	pod string

	iface string
}

func (o *monitorOptions) Complete() error {
	if o.pod == "" {
		return errors.New("pod arg is empty.")
	}

	ss := strings.Split(o.pod, "/")
	if len(ss) != 2 {
		return fmt.Errorf("Pod %s is not in the format of namespace/name", o.pod)
	}
	namespace, name := ss[0], ss[1]
	pod, err := kubeClient.Pods(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	podIP := net.ParseIP(pod.Status.PodIP)
	routes, err := netlink.RouteGet(podIP)
	if err != nil {
		return err
	}

	if len(routes) < 1 {
		return fmt.Errorf("couldn't find veth interface for pod %q", o.pod)
	}

	iface, err := net.InterfaceByIndex(routes[0].LinkIndex)
	if err != nil {
		return err
	}

	if iface.Name == "eth0" {
		return fmt.Errorf("Pod %q is not on this node.\n", o.pod)
	}
	fmt.Printf("Listening for packets at %q interface\n", iface.Name)

	capturePackets(iface.Name)
	return nil
}

func monitorCmd() *cobra.Command {
	o := monitorOptions{}

	cmd := &cobra.Command{
		Use:   "monitor [--pod=NAMESPACE/NAME]",
		Short: "Monitors packets at veth interface of a Pod.",
		Run: func(cmd *cobra.Command, args []string) {
			checkErr(o.Complete())
		},
	}

	cmd.Flags().StringVarP(&o.pod, "pod", "p", o.pod, "pod that needs to be probed.")
	return cmd
}

func init() {
	rootCmd.AddCommand(monitorCmd())
}
