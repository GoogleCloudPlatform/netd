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
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type statusOptions struct {
	node    string
	pod     string
	service string

	addrs []net.Addr
}

func (o *statusOptions) Complete() error {
	if o.node != "" {
		node, err := kubeClient.Nodes().Get(o.node, metav1.GetOptions{})
		if err != nil {
			return err
		}

		for _, a := range node.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				fmt.Printf("Node %q has IP Address %q\n", o.node, a.Address)
				o.addrs = append(o.addrs, &net.IPAddr{IP: net.ParseIP(a.Address)})
			}
		}
	}

	if o.pod != "" {
		ss := strings.Split(o.pod, "/")
		if len(ss) != 2 {
			return fmt.Errorf("Pod %s is not in the format of namespace/name", o.pod)
		}
		namespace, name := ss[0], ss[1]
		pod, err := kubeClient.Pods(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		fmt.Printf("Pod %q has IP Address %q\n", o.pod, pod.Status.PodIP)
		o.addrs = append(o.addrs, &net.IPAddr{IP: net.ParseIP(pod.Status.PodIP)})
	}

	if o.service != "" {
		ss := strings.Split(o.service, "/")
		if len(ss) != 2 {
			return fmt.Errorf("Service %s is not in the format of namespace/name", o.service)
		}
		namespace, name := ss[0], ss[1]
		service, err := kubeClient.Services(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if service.Spec.Type != corev1.ServiceTypeClusterIP {
			return fmt.Errorf("%s is of type %s, only ClusterIP type supported", o.service, service.Spec.Type)
		}

		ip := net.ParseIP(service.Spec.ClusterIP)
		for _, port := range service.Spec.Ports {
			if port.Protocol == corev1.ProtocolTCP {
				fmt.Printf("Service %q has Address %s:%d\n", o.service, ip, port.Port)
				o.addrs = append(o.addrs, &net.TCPAddr{IP: ip, Port: int(port.Port)})
			}
		}
	}

	return nil
}

func (o statusOptions) SendProbe() error {
	var err error
	for _, addr := range o.addrs {
		switch addr.(type) {
		case *net.IPAddr:
			traceICMPProbe()
			err = multierr.Append(err, sendICMPProbe(addr.(*net.IPAddr)))
		case *net.TCPAddr:
			err = multierr.Append(err, sendTCPProbe(addr.(*net.TCPAddr)))
		default:
			err = multierr.Append(err, fmt.Errorf("Address %v is of unknown type %T", addr, addr))
		}
	}

	return err
}

func statusCmd() *cobra.Command {
	o := statusOptions{}

	cmd := &cobra.Command{
		Use:   "status [--node=NODE] [--pod=NAMESPACE/NAME] [--service=NAMESPACE/NAME]",
		Short: "Send a probe to node, pod or service.",
		Run: func(cmd *cobra.Command, args []string) {
			checkErr(o.Complete())
			checkErr(o.SendProbe())
		},
	}

	cmd.Flags().StringVarP(&o.node, "node", "n", o.node, "node that needs to be probed.")
	cmd.Flags().StringVarP(&o.pod, "pod", "p", o.pod, "pod that needs to be probed.")
	cmd.Flags().StringVarP(&o.service, "service", "s", o.service, "service that needs to be probed.")
	return cmd
}

func init() {
	rootCmd.AddCommand(statusCmd())
}
