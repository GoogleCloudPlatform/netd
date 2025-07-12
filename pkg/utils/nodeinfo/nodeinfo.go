package nodeinfo

import (
	"fmt"
	"os"

	v1 "k8s.io/api/core/v1"
)

// GetNodeName returns the current node name.
func GetNodeName() (string, error) {
	nodeName := os.Getenv("CURRENT_NODE_NAME")
	if nodeName != "" {
		return nodeName, nil
	}
	return os.Hostname()
}

// GetPodCIDRs returns all PodCIDRs from the given node.
func GetPodCIDRs(node *v1.Node) ([]string, error) {
	if len(node.Spec.PodCIDRs) != 0 {
		return node.Spec.PodCIDRs, nil
	}
	if node.Spec.PodCIDR == "" {
		return nil, fmt.Errorf("both podCIDR and podCIDRs are empty")
	}
	return []string{node.Spec.PodCIDR}, nil
}
