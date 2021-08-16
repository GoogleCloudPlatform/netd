// Package inetdiag provides basic structs and utilities for INET_DIAG messaages.
// Based on uapi/linux/inet_diag.h.
package inetdiag

import (
	"fmt"
	"syscall"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/tcp"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Pretty basic code slightly adapted from code copied from
// https://gist.github.com/gwind/05f5f649d93e6015cf47ffa2b2fd9713
// Original source no longer available at https://github.com/eleme/netlink/blob/master/inetdiag.go

// Adaptations are Copyright 2018 M-Lab Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* IMPORTANT NOTES
This 2002 article describes Netlink Sockets
https://pdfs.semanticscholar.org/6efd/e161a2582ba5846e4b8fea5a53bc305a64f3.pdf

"Netlink messages are aligned to 32 bits and, generally speaking, they contain data that is
expressed in host-byte order"
*/

// inet_diag.h

// NOTE: darwin unix.AF_INET6 and syscall.AF_INET6 are incorrect for
// our purposes (0x1e), so, we set this explicitly.
const AF_INET6 = 0x0a

// NOTE: windows does not have unix.AF_INET available.
const AF_INET = 0x02

const (
	INET_DIAG_NONE = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN
	INET_DIAG_DCTCPINFO
	INET_DIAG_PROTOCOL
	INET_DIAG_SKV6ONLY
	INET_DIAG_LOCALS
	INET_DIAG_PEERS
	INET_DIAG_PAD
	INET_DIAG_MARK
	INET_DIAG_BBRINFO
	INET_DIAG_CLASS_ID
	INET_DIAG_MD5SIG
	// TODO - Should check whether this matches the current linux header.
	INET_DIAG_MAX
)

// InetDiagType provides human readable strings for decoding attribute types.
var InetDiagType = map[int32]string{
	INET_DIAG_MEMINFO:   "MemInfo",
	INET_DIAG_INFO:      "TCPInfo",
	INET_DIAG_VEGASINFO: "Vegas",
	INET_DIAG_CONG:      "Congestion",
	INET_DIAG_TOS:       "TOS",
	INET_DIAG_TCLASS:    "TClass",
	INET_DIAG_SKMEMINFO: "SKMemInfo",
	INET_DIAG_SHUTDOWN:  "Shutdown",
	INET_DIAG_DCTCPINFO: "DCTCPInfo",
	INET_DIAG_PROTOCOL:  "Protocol",
	INET_DIAG_SKV6ONLY:  "SKV6Only",
	INET_DIAG_LOCALS:    "Locals",
	INET_DIAG_PEERS:     "Peers",
	INET_DIAG_PAD:       "Pad",
	INET_DIAG_MARK:      "Mark",
	INET_DIAG_BBRINFO:   "BBRInfo",
	INET_DIAG_CLASS_ID:  "ClassID",
	INET_DIAG_MD5SIG:    "MD5Sig",
}

var diagFamilyMap = map[uint8]string{
	AF_INET:  "tcp",
	AF_INET6: "tcp6", // because darwin values for AF_INET6 are incorrect.
}

// Protocol defines the type corresponding to INET_DIAG_PROTOCOL 8 bit field.
type Protocol uint8

const (
	// Protocol_IPPROTO_UNUSED ...
	Protocol_IPPROTO_UNUSED Protocol = 0
	// Protocol_IPPROTO_TCP    indicates TCP traffic.
	Protocol_IPPROTO_TCP Protocol = 6
	// Protocol_IPPROTO_UDP   indicates UDP traffic.
	Protocol_IPPROTO_UDP Protocol = 17
	// Protocol_IPPROTO_DCCP indicates DCCP traffic.
	Protocol_IPPROTO_DCCP Protocol = 33
)

// ProtocolName is used to convert Protocol values to strings.
var ProtocolName = map[int32]string{
	0:  "IPPROTO_UNUSED",
	6:  "IPPROTO_TCP",
	17: "IPPROTO_UDP",
	33: "IPPROTO_DCCP",
}

// TODO - Figure out why we aren't seeing INET_DIAG_DCTCPINFO or INET_DIAG_BBRINFO messages.
func MakeReq(inetType uint8) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST)
	msg := NewReqV2(inetType, syscall.IPPROTO_TCP,
		tcp.AllFlags & ^((1<<uint(tcp.SYN_RECV))|(1<<uint(tcp.TIME_WAIT))|(1<<uint(tcp.CLOSE))))
	msg.IDiagExt |= (1 << (INET_DIAG_MEMINFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_INFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_VEGASINFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_CONG - 1))

	msg.IDiagExt |= (1 << (INET_DIAG_TCLASS - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_TOS - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_SKMEMINFO - 1))
	msg.IDiagExt |= (1 << (INET_DIAG_SHUTDOWN - 1))

	req.AddData(msg)
	req.NlMsghdr.Type = SOCK_DIAG_BY_FAMILY
	req.NlMsghdr.Flags |= syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST
	return req
}

func ProcessMessage(m *syscall.NetlinkMessage, seq uint32, pid uint32) (msg *syscall.NetlinkMessage, shouldContinue bool, err error) {
	if m.Header.Seq != seq {
		fmt.Printf("Wrong Seq nr %d, expected %d", m.Header.Seq, seq)
		return nil, false, ErrBadSequence
	}
	if m.Header.Pid != pid {
		fmt.Printf("Wrong pid %d, expected %d", m.Header.Pid, pid)
		return nil, false, ErrBadPid
	}
	if m.Header.Type == unix.NLMSG_DONE {
		return nil, false, nil
	}
	if m.Header.Type == unix.NLMSG_ERROR {
		native := nl.NativeEndian()
		if len(m.Data) < 4 {
			return nil, false, ErrBadMsgData
		}
		error := int32(native.Uint32(m.Data[0:4]))
		if error == 0 {
			return nil, false, nil
		}
		fmt.Println(syscall.Errno(-error))

	}
	if m.Header.Flags&unix.NLM_F_MULTI == 0 {
		return m, false, nil
	}
	return m, true, nil
}
