// Package tcp provides TCP state constants and string coversions for those
// constants.
package tcp

import "fmt"

// State is the enumeration of TCP states.
// https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/
// and uapi/linux/tcp.h
type State int32

// All of these constants' names make the linter complain, but we inherited
// these names from external C code, so we will keep them.
const (
	INVALID     State = 0
	ESTABLISHED State = 1
	SYN_SENT    State = 2
	SYN_RECV    State = 3
	FIN_WAIT1   State = 4
	FIN_WAIT2   State = 5
	TIME_WAIT   State = 6
	CLOSE       State = 7
	CLOSE_WAIT  State = 8
	LAST_ACK    State = 9
	LISTEN      State = 10
	CLOSING     State = 11
)

// AllFlags includes flag bits for all TCP connection states. It corresponds to TCPF_ALL in some linux code.
const AllFlags = 0xFFF

var stateName = map[State]string{
	0:  "INVALID",
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
}

func (x State) String() string {
	s, ok := stateName[x]
	if !ok {
		return fmt.Sprintf("UNKNOWN_STATE_%d", x)
	}
	return s
}

// LinuxTCPInfo is the linux defined structure returned in RouteAttr DIAG_INFO messages.
// It corresponds to the struct tcp_info in
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/tcp.h
type LinuxTCPInfo struct {
	State       uint8
	CAState     uint8
	Retransmits uint8
	Probes      uint8
	Backoff     uint8
	Options     uint8
	WScale      uint8
	AppLimited  uint8

	RTO    uint32
	ATO    uint32
	SndMSS uint32
	RcvMSS uint32

	Unacked uint32
	Sacked  uint32
	Lost    uint32
	Retrans uint32
	Fackets uint32

	/* Times. */
	// These seem to be elapsed time, so they increase on almost every sample.
	// We can probably use them to get more info about intervals between samples.
	LastDataSent uint32
	LastAckSent  uint32
	LastDataRecv uint32
	LastAckRecv  uint32

	/* Metrics. */
	PMTU        uint32
	RcvSsThresh uint32
	RTT         uint32
	RTTVar      uint32
	SndSsThresh uint32
	SndCwnd     uint32
	AdvMSS      uint32
	Reordering  uint32

	RcvRTT   uint32
	RcvSpace uint32

	TotalRetrans uint32

	PacingRate    int64
	MaxPacingRate int64

	BytesAcked    uint64
	BytesReceived uint64
	SegsOut       uint32
	SegsIn        uint32

	NotsentBytes uint32
	MinRTT       uint32
	DataSegsIn   uint32
	DataSegsOut  uint32

	DeliveryRate uint64

	BusyTime      int64
	RWndLimited   int64
	SndBufLimited int64

	Delivered   uint32
	DeliveredCE uint32

	BytesSent    uint64
	BytesRetrans uint64

	DSackDups uint32
	ReordSeen uint32

	RcvOooPack uint32

	SndWnd uint32
}
