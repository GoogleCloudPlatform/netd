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
	"fmt"
	"syscall"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/inetdiag"
	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/parser"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink/nl"
)

var (
	TCPConnectionsDesc = prometheus.NewDesc(
		"tcp_connections",
		"Current amount of tcp connections on a node",
		nil, nil,
	)

	ActiveTCPRetransmits = prometheus.NewDesc(
		"active_tcp_retransmits",
		"Current amount of tcp retransmits on a node",
		nil, nil,
	)
)

func getSnapshots(req *nl.NetlinkRequest) ([]*parser.Snapshot, error) {
	var snps []*parser.Snapshot
	sockType := syscall.NETLINK_INET_DIAG
	s, err := nl.Subscribe(sockType)
	if err != nil {
		return nil, err
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
	return snps, nil
}

type netlinkCollector struct {
}

func init() {
	registerCollector("netlink_metrics", NewNetlinkCollector)
}

func NewNetlinkCollector() (Collector, error) {
	return &netlinkCollector{}, nil
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
	snapshots, err := getRequests()
	if err != nil {
		return fmt.Errorf("could not get tcp requests: %q", err)
	}
	retransmits := getRetransmits(snapshots)
	ch <- prometheus.MustNewConstMetric(TCPConnectionsDesc, prometheus.GaugeValue, float64(len(snapshots)))
	ch <- prometheus.MustNewConstMetric(TCPConnectionsDesc, prometheus.GaugeValue, float64(retransmits))
	return nil
}
