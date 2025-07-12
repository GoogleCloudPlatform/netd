package nodeinfo

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
)

func TestGetPodCIDRs(t *testing.T) {
	testCases := []struct {
		desc         string
		node         *v1.Node
		wantPodCIDRs []string
		wantErr      bool
	}{
		{
			desc: "working case with podCIDR",
			node: &v1.Node{
				Spec: v1.NodeSpec{
					PodCIDR: "10.124.0.0/16",
				},
			},
			wantPodCIDRs: []string{"10.124.0.0/16"},
			wantErr:      false,
		},
		{
			desc: "working case with podCIDRs",
			node: &v1.Node{
				Spec: v1.NodeSpec{
					PodCIDRs: []string{"10.124.0.0/16"},
				},
			},
			wantPodCIDRs: []string{"10.124.0.0/16"},
			wantErr:      false,
		},
		{
			desc:    "missing podCIDR",
			node:    &v1.Node{},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		podCIDRs, err := GetPodCIDRs(tc.node)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("GetPodCIDRs() error = %v", err)
			}
			continue
		}
		if !reflect.DeepEqual(podCIDRs, tc.wantPodCIDRs) {
			t.Errorf("GetPodCIDRs() podCIDRs = %v, want %v", podCIDRs, tc.wantPodCIDRs)
		}
	}
}
