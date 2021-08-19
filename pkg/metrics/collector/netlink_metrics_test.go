/*
Copyright 2021 Google Inc.

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

package collector

import (
	"testing"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/inetdiag"
	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/parser"
	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/tcp"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCreateStatMap(t *testing.T) {
	myPod := &v1.Pod{metav1.TypeMeta{}, metav1.ObjectMeta{Name: "pod", Namespace: "default"}, v1.PodSpec{}, v1.PodStatus{}}
	ipMap.ipMap = map[string]*v1.Pod{"my-ip": myPod}

	tcpInfo := tcp.LinuxTCPInfo{Retrans: 4}
	sockInfoSrc := inetdiag.SockID{SrcIP: "my-ip"}
	sockInfoDst := inetdiag.SockID{DstIP: "my-ip"}

	mySnapshotSrc := parser.Snapshot{SockInfo: &sockInfoSrc, TCPInfo: &tcpInfo}
	mySnapshotDst := parser.Snapshot{SockInfo: &sockInfoDst, TCPInfo: &tcpInfo}

	snapshots := []*parser.Snapshot{&mySnapshotSrc, &mySnapshotDst}

	statMap := createStatMap(snapshots)
	want := map[*v1.Pod]netlinkStats{myPod: {retransmits: 8, tcpConnections: 2}}
	if statMap[myPod] != want[myPod] {
		t.Fatalf("Fatal, got %+q, wanted %+q", statMap, want)
	}
}

func TestSafeIPAdd(t *testing.T) {
	myPod := &v1.Pod{metav1.TypeMeta{}, metav1.ObjectMeta{Name: "pod", Namespace: "default"}, v1.PodSpec{}, v1.PodStatus{}}
	ipMap.safeIPWrite("my-ip", myPod)
	if ipMap.ipMap["my-ip"] != myPod {
		t.Fatalf("Fatal, got %+q, wanted %+q", ipMap.ipMap["my-ip"], myPod)
	}
}

func TestSafeIPDelete(t *testing.T) {
	myPod := &v1.Pod{metav1.TypeMeta{}, metav1.ObjectMeta{Name: "pod", Namespace: "default"}, v1.PodSpec{}, v1.PodStatus{}}

	ipMap.safeIPWrite("my-ip", myPod)
	ipMap.safeIPDelete("my-ip")
	if _, ok := ipMap.ipMap["my-ip"]; ok {
		t.Fatalf("Fatal, got %+q, wanted nothing", ipMap.ipMap["my-ip"])
	}
}

func TestSafeIPRead(t *testing.T) {
	myPod := &v1.Pod{metav1.TypeMeta{}, metav1.ObjectMeta{Name: "pod", Namespace: "default"}, v1.PodSpec{}, v1.PodStatus{}}

	ipMap.safeIPWrite("my-ip", myPod)
	got, ok := ipMap.safeIPRead("my-ip")
	if myPod != got || !ok {
		t.Fatalf("Fatal, got %+q, wanted %+q", ipMap.ipMap["my-ip"], myPod)
	}

	_, ok = ipMap.safeIPRead("my-ip1")
	if ok {
		t.Fatalf("Fatal, read from empty key returns ok")
	}
}
