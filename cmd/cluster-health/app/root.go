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
	"os"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

var (
	kubeClient v1.CoreV1Interface
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cluster-health",
	Short: "cluster-health CLI to troubleshoot GKE Networking Datapath",
	Run:   func(cmd *cobra.Command, args []string) {},
}

func checkErr(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(-1)
}

// Execute adds all child commands to the root command sets flags appropriately.
func Execute() {
	checkErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	kubeConfig, err := rest.InClusterConfig()
	checkErr(err)

	client, err := kubernetes.NewForConfig(kubeConfig)
	checkErr(err)

	kubeClient = client.CoreV1()
}
