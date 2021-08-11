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
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestComplete(t *testing.T) {
	// Test data
	client := fake.NewSimpleClientset()
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node-1",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				corev1.NodeAddress{
					Type:    corev1.NodeInternalIP,
					Address: "10.1.128.0",
				},
			},
		},
	}
	client.CoreV1().Nodes().Create(node)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-1",
			Namespace: "test-ns",
		},
		Status: corev1.PodStatus{
			PodIP: "10.1.10.0",
		},
	}
	client.CoreV1().Pods("test-ns").Create(pod)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc-1",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.0.50.0",
			Ports: []corev1.ServicePort{
				corev1.ServicePort{
					Port:     int32(443),
					Protocol: corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
	client.CoreV1().Services("test-ns").Create(svc)

	// Tests
	cases := []struct {
		desc    string
		opts    statusOptions
		wantErr bool
		want    []net.Addr
	}{
		{
			desc: "empty-input",
		},
		{
			desc: "node-input",
			opts: statusOptions{
				node: "test-node-1",
			},
			want: []net.Addr{
				&net.IPAddr{IP: net.ParseIP("10.1.128.0")},
			},
		},
		{
			desc: "node-does-not-exist",
			opts: statusOptions{
				node: "test-non-existent-node",
			},
			wantErr: true,
		},

		{
			desc: "pod-input",
			opts: statusOptions{
				pod: "test-ns/test-pod-1",
			},
			want: []net.Addr{
				&net.IPAddr{IP: net.ParseIP("10.1.10.0")},
			},
		},
		{
			desc: "pod-invalid-input",
			opts: statusOptions{
				pod: "test-pod-1",
			},
			wantErr: true,
		},
		{
			desc: "pod-does-not-exist",
			opts: statusOptions{
				pod: "test-ns/test-non-existent-pod",
			},
			wantErr: true,
		},
		{
			desc: "svc-input",
			opts: statusOptions{
				service: "test-ns/test-svc-1",
			},
			want: []net.Addr{
				&net.TCPAddr{IP: net.ParseIP("10.0.50.0"), Port: 443},
			},
		},
		{
			desc: "svc-invalid-input",
			opts: statusOptions{
				service: "test-svc-1",
			},
			wantErr: true,
		},
		{
			desc: "svc-does-not-exist",
			opts: statusOptions{
				service: "test-ns/test-non-existent-pod",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			kubeClient = client.CoreV1()
			err := tc.opts.Complete()
			if err != nil && !tc.wantErr {
				t.Fatalf("Complete returned error %v, want nil error", err)
			}
			if err == nil && tc.wantErr {
				t.Fatal("Complete returned nil, want error")
			}

			got := tc.opts.addrs
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("output differed:\n%s", diff)
			}
		})
	}
}
