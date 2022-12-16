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
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/inetdiag"
	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/parser"
	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/tcp"
)

// Note, a sum over the pod tcp connections/ retransmits != the same value
// as the node aggregates. This is because the node aggregates don't just
// sum over pod namespaces but all namespaces including the default one.
var (
	NodeTCPConnectionsDesc = prometheus.NewDesc(
		"node_tcp_connections",
		"Current amount of tcp connections on a node",
		nil, nil,
	)

	NodeActiveTCPRetransmits = prometheus.NewDesc(
		"node_tcp_retransmits",
		"Current amount of tcp retransmits on a node",
		nil, nil,
	)

	TCPConnectionsDesc = prometheus.NewDesc(
		"active_tcp_connections",
		"Number of active TCP connections by hosted pod name/namespace",
		[]string{"pod_name", "namespace_name"}, nil,
	)

	ActiveTCPRetransmits = prometheus.NewDesc(
		"active_tcp_retransmits",
		"Number of retransmits on active TCP connections by hosted pod name/namespace",
		[]string{"pod_name", "namespace_name"}, nil,
	)
)

type netlinkCollector struct {
}

type netlinkStats struct {
	retransmits    uint64
	tcpConnections uint64
}

var (
	ipMap          = initIPMap()
	nodeName       = os.Getenv("CURRENT_NODE_NAME")
	enablePodWatch bool
	firstRun       = true
)

func init() {
	flag.BoolVar(&enablePodWatch, "enable-pod-watch", false, "Enable pod watch on netlink_metrics")
	registerCollector("netlink_metrics", NewNetlinkCollector)
}

// Functionality for multithreaded map usage.

type safeIPMap struct {
	// Protects the map from multiple writes
	mapMux sync.RWMutex
	ipMap  map[string]*v1.Pod
}

func initIPMap() *safeIPMap {
	var newIPMap safeIPMap
	newIPMap.ipMap = make(map[string]*v1.Pod)
	return &newIPMap
}

func (curMap *safeIPMap) safeIPWrite(key string, value *v1.Pod) {
	curMap.mapMux.Lock()
	defer curMap.mapMux.Unlock()
	curMap.ipMap[key] = value
}

func (curMap *safeIPMap) safeIPDelete(key string) {
	curMap.mapMux.Lock()
	defer curMap.mapMux.Unlock()
	delete(curMap.ipMap, key)
}

func (curMap *safeIPMap) safeIPRead(key string) (*v1.Pod, bool) {
	curMap.mapMux.RLock()
	defer curMap.mapMux.RUnlock()
	podDef, ok := curMap.ipMap[key]
	return podDef, ok
}

// Functionality for pod watching.
func createPodWatch() error {
	// Creates the in-cluster config.
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	watchlist := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"pods",
		v1.NamespaceAll,
		fields.OneTermEqualSelector("spec.nodeName", nodeName),
	)
	_, controller := cache.NewInformer(
		watchlist,
		&v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    onPodAdd,
			UpdateFunc: onPodUpdate,
			DeleteFunc: onPodDelete,
		},
	)

	stopper := make(chan struct{})

	go controller.Run(stopper)

	if !cache.WaitForCacheSync(stopper, controller.HasSynced) {
		glog.Infof("Timed out waiting for caches to sync.")
	}

	return nil
}

func hasPodIP(pod *v1.Pod) bool {
	// Pod not assigned.
	if pod.Status.PodIP == "" {
		return false
	}
	// Pod running on host network.
	if pod.Status.PodIP == pod.Status.HostIP {
		return false
	}
	return true
}

func onPodAdd(podObj interface{}) {
	pod := podObj.(*v1.Pod)
	if hasPodIP(pod) {
		ipMap.safeIPWrite(pod.Status.PodIP, pod)
	}
}

func onPodUpdate(oldPod, newPod interface{}) {
	prevPod := oldPod.(*v1.Pod)
	pod := newPod.(*v1.Pod)
	if prevPod.Status.PodIP == pod.Status.PodIP {
		return
	}
	if hasPodIP(prevPod) {
		ipMap.safeIPDelete(prevPod.Status.PodIP)
	}
	if hasPodIP(pod) {
		ipMap.safeIPWrite(pod.Status.PodIP, pod)
	}
	glog.Infof("pods are: %+q", ipMap.ipMap)
}

func onPodDelete(podObj interface{}) {
	pod := podObj.(*v1.Pod)
	if hasPodIP(pod) {
		ipMap.safeIPDelete(pod.Status.PodIP)
	}
}

func updatePodStats(stats netlinkStats, tcpInfo *tcp.LinuxTCPInfo) netlinkStats {
	stats.tcpConnections++
	if tcpInfo == nil {
		return stats
	}
	stats.retransmits += uint64(tcpInfo.Retrans)
	return stats
}

func createStatMap(snapshots []*parser.Snapshot) map[*v1.Pod]netlinkStats {
	statMap := make(map[*v1.Pod]netlinkStats)
	for _, snapshot := range snapshots {
		if snapshot.SockInfo == nil {
			continue
		}
		if pod, ok := ipMap.safeIPRead(snapshot.SockInfo.SrcIP); ok {
			statMap[pod] = updatePodStats(statMap[pod], snapshot.TCPInfo)
		}

		if pod, ok := ipMap.safeIPRead(snapshot.SockInfo.DstIP); ok {
			statMap[pod] = updatePodStats(statMap[pod], snapshot.TCPInfo)
		}
	}
	return statMap
}

func NewNetlinkCollector() (Collector, error) {
	return &netlinkCollector{}, nil
}

func getNamespaces() ([]netns.NsHandle, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0)
	for _, f := range files {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	nsSet := make(map[uint64]netns.NsHandle)
	var s unix.Stat_t
	for _, pid := range pids {
		ns, err := netns.GetFromPid(pid)
		if err != nil {
			continue
		}
		// Check for a new inode.
		if err := unix.Fstat(int(ns), &s); err != nil {
			continue
		}
		if _, ok := nsSet[s.Ino]; ok {
			ns.Close()
			continue
		}
		nsSet[s.Ino] = ns
	}
	namespaces := make([]netns.NsHandle, 0)
	for _, ns := range nsSet {
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

func getSnapshots(req *nl.NetlinkRequest) ([]*parser.Snapshot, error) {
	var snps []*parser.Snapshot
	sockType := syscall.NETLINK_INET_DIAG
	namespaces, err := getNamespaces()
	if err != nil {
		return nil, err
	}
	basens, err := netns.Get()
	if err != nil {
		return nil, err
	}
	for _, curNs := range namespaces {
		defer curNs.Close()
		s, err := nl.SubscribeAt(curNs, basens, sockType)
		if err != nil {
			glog.Infof("Could not subscribe to netlink namespaces %q", curNs)
			continue
		}
		defer s.Close()
		if err := s.Send(req); err != nil {
			return nil, err
		}
		pid, err := s.GetPid()
		if err != nil {
			return nil, err
		}
		// Adapted this from req.Execute in nl_linux.go
	snapshotLoop:
		for {
			msgs, _, err := s.Receive()
			if err != nil {
				return nil, err
			}
			// TODO avoid the copy.
			for i := range msgs {
				m, shouldContinue, err := inetdiag.ProcessMessage(&msgs[i], req.Seq, pid)
				if err != nil {
					return nil, err
				}
				if m != nil {
					cur, err := parser.MakeSnapShot(m, true)

					if cur == nil || err != nil {
						continue
					}
					snps = append(snps, cur)
				}
				if !shouldContinue {
					break snapshotLoop
				}
			}

		}
	}

	return snps, nil
}

func getRequests() ([]*parser.Snapshot, error) {
	req6 := inetdiag.MakeReq(syscall.AF_INET6)
	req := inetdiag.MakeReq(syscall.AF_INET)
	res6, err := getSnapshots(req6)
	if err != nil {
		return nil, fmt.Errorf("error getting req6: %q", err)
	}
	res, err := getSnapshots(req)
	if err != nil {
		return nil, fmt.Errorf("error getting req: %q", err)
	}
	return append(res, res6...), nil
}

func getRetransmits(snapshots []*parser.Snapshot) uint64 {
	var retransmits uint64
	retransmits = 0
	for _, snap := range snapshots {
		if snap == nil || snap.TCPInfo == nil {
			continue
		}
		retransmits += uint64(snap.TCPInfo.Retrans)
	}
	return retransmits
}

func (c *netlinkCollector) Update(ch chan<- prometheus.Metric) error {
	if enablePodWatch && firstRun {
		if err := createPodWatch(); err != nil {
			glog.Infof("Error, pod watch not running with err, %q", err)
		}
		firstRun = false
	}

	snapshots, err := getRequests()
	if err != nil {
		return fmt.Errorf("could not get tcp requests: %q", err)
	}

	retransmits := getRetransmits(snapshots)
	ch <- prometheus.MustNewConstMetric(NodeTCPConnectionsDesc, prometheus.GaugeValue, float64(len(snapshots)))
	ch <- prometheus.MustNewConstMetric(NodeActiveTCPRetransmits, prometheus.GaugeValue, float64(retransmits))

	if !enablePodWatch {
		return nil
	}

	statMap := createStatMap(snapshots)
	for pod, stats := range statMap {
		ch <- prometheus.MustNewConstMetric(TCPConnectionsDesc, prometheus.GaugeValue,
			float64(stats.tcpConnections), pod.ObjectMeta.Name, pod.ObjectMeta.Namespace)
		ch <- prometheus.MustNewConstMetric(ActiveTCPRetransmits, prometheus.GaugeValue,
			float64(stats.retransmits), pod.ObjectMeta.Name, pod.ObjectMeta.Namespace)
	}
	return nil
}
