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
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func sendICMPProbe(addr *net.IPAddr) error {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}

	if _, err := c.WriteTo(wb, addr); err != nil {
		return err
	}

	rb := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return err
	}
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return err
	}
	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return err
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
	//	fmt.Printf("IP %s reachable via ICMP probe\n", peer)
	default:
		//	fmt.Printf("got %+v; want echo reply\n", rm)
	}

	return nil
}

func sendTCPProbe(addr *net.TCPAddr) error {
	laddr := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	laddr = listener.Addr().(*net.TCPAddr)
	listener.Close()

	conn, err := net.DialTCP("tcp", laddr, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	time.Sleep(5 * time.Second)

	fmt.Printf("Found TCP SYN with source port %d\n", laddr.Port)
	fmt.Printf("Found TCP SYN-ACK with source port %d\n", laddr.Port)
	fmt.Printf("Found TCP ACK with source port %d\n", laddr.Port)

	return nil
}

func capturePackets(device string) {
	ipInfo := ipToResource()

	handle, err := pcap.OpenLive(device, 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet, ipInfo)
	}
}

func ipToResource() map[string]string {
	ret := make(map[string]string)
	podsList, err := kubeClient.Pods("").List(metav1.ListOptions{})
	if err != nil {
		return ret
	}
	for _, pod := range podsList.Items {
		if !pod.Spec.HostNetwork {
			ret[pod.Status.PodIP] = fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
		}
	}

	svcsList, err := kubeClient.Services("").List(metav1.ListOptions{})
	if err != nil {
		return ret
	}
	for _, svc := range svcsList.Items {
		if svc.Spec.Type == corev1.ServiceTypeClusterIP {
			ret[svc.Spec.ClusterIP] = fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
		}
	}

	return ret
}

func printPacketInfo(pkt gopacket.Packet, ipInfo map[string]string) {
	const pktTmpl = "{{.SrcIP}}{{if .SrcPort}}:{{.SrcPort}}{{end}} -> {{.DstIP}}{{if .DstPort}}:{{.DstPort}}{{end}} {{.Protocol}}"
	data := make(map[string]interface{})
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if res, ok := ipInfo[ip.SrcIP.String()]; ok {
			data["SrcIP"] = res
		} else {
			data["SrcIP"] = ip.SrcIP
		}
		if res, ok := ipInfo[ip.DstIP.String()]; ok {
			data["DstIP"] = res
		} else {
			data["DstIP"] = ip.DstIP
		}
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		data["SrcPort"] = tcp.SrcPort
		data["DstPort"] = tcp.DstPort
		data["Protocol"] = "TCP"
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		data["SrcPort"] = udp.SrcPort
		data["DstPort"] = udp.DstPort
		data["Protocol"] = "UDP"
	}

	t := template.Must(template.New("packet").Parse(pktTmpl))
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, data); err != nil {
		log.Fatal(err)
	}

	s := buf.String()
	if len(s) > 10 {
		fmt.Println(s)
	}
}
