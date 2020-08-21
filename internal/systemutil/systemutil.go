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

// Package systemutil defines the system/platform related interfaces and utils.
package systemutil

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type SysctlFunc func(name string, params ...string) (string, error)

type NIC struct {
	Route netlink.Route
	Link  netlink.LinkAttrs
}

var ErrFailedRoute = errors.New("failed to get route for IP")
var ErrFailedLink = errors.New("failed to get the link by index")

func GetNIC(ip net.IP) (*NIC, error) {
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (%v)", ErrFailedRoute, ip, err)
	}
	route := routes[0]

	l, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (%v)", ErrFailedLink, route.LinkIndex, err)
	}

	link := l.Attrs()

	return &NIC{
		Route: route,
		Link:  *link,
	}, nil
}

func GetNodeSpec(ctx context.Context, nodeName string) (*v1.Node, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return node, nil
}
