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
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		return err
	}
	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		return err
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeEcho:
		fmt.Printf("IP %s reachable via ICMP probe\n", peer)
	default:
		fmt.Printf("got %+v; want echo reply\n", rm)
	}

	return nil
}

func sendTCPProbe(addr *net.TCPAddr) error {
	laddr := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Println(listener.Addr())

	return nil
}
