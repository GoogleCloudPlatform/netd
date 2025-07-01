package utils

import (
	"fmt"
	"os"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewClientSet returns a clientset using in cluster config.
func NewClientSet() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating in-cluster config: %v", err)
	}
	config.ContentType = runtime.ContentTypeProtobuf

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset: %v", err)
	}

	return clientset, nil
}

// GetNodeName returns the current node name.
func GetNodeName() (string, error) {
	var err error
	nodeName := os.Getenv("CURRENT_NODE_NAME")
	if nodeName == "" {
		nodeName, err = os.Hostname()
		if err != nil {
			return "", fmt.Errorf("error getting hostname: %v", err)
		}
	}
	return nodeName, nil
}

// GetPodCIDRs returns all PodCIDRs from the given node.
func GetPodCIDRs(node *v1.Node) ([]string, error) {
	podCIDRs := node.Spec.PodCIDRs
	if len(podCIDRs) == 0 {
		if node.Spec.PodCIDR == "" {
			return nil, fmt.Errorf("both podCIDR and podCIDRs are empty")
		}
		podCIDRs = []string{node.Spec.PodCIDR}
	}
	return podCIDRs, nil
}
