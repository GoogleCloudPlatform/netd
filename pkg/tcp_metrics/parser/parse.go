package parser

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/inetdiag"
	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/tcp"
)

// Snapshot contains all info gathered through netlink library.
type Snapshot struct {
	// Timestamp of batch of messages containing this message.
	Timestamp time.Time

	// Bit field indicating whether each message type was observed.
	Observed uint32

	// Bit field indicating whether any message type was NOT fully parsed.
	// TODO - populate this field if any message is ignored, or not fully parsed.
	NotFullyParsed uint32

	// Info from struct inet_diag_msg, including socket_id;
	InetDiagMsg *inetdiag.InetDiagMsg

	SockInfo *inetdiag.SockID
	// From INET_DIAG_CONG message.
	CongestionAlgorithm string

	// See https://tools.ietf.org/html/rfc3168
	// TODO Do we need to record whether these are present and zero, vs absent?
	TOS     uint8
	TClass  uint8
	ClassID uint8

	// TODO Do we need to record present and zero, vs absent?
	Shutdown uint8

	// From INET_DIAG_PROTOCOL message.
	// TODO Do we need to record present and zero, vs absent?
	Protocol inetdiag.Protocol

	Mark uint32

	// TCPInfo contains data from struct tcp_info.
	TCPInfo *tcp.LinuxTCPInfo

	// Data obtained from INET_DIAG_MEMINFO.
	MemInfo *inetdiag.MemInfo

	// Data obtained from INET_DIAG_SKMEMINFO.
	SocketMem *inetdiag.SocketMemInfo

	VegasInfo *inetdiag.VegasInfo
	DCTCPInfo *inetdiag.DCTCPInfo
	BBRInfo   *inetdiag.BBRInfo
}

// ParseRouteAttr parses a byte array into slice of NetlinkRouteAttr struct.
// Derived from "github.com/vishvananda/netlink/nl/nl_linux.go"
func ParseRouteAttr(b []byte) ([]NetlinkRouteAttr, error) {
	var attrs []NetlinkRouteAttr
	for len(b) >= SizeofRtAttr {
		a, vbuf, alen, err := netlinkRouteAttrAndValue(b)
		if err != nil {
			return nil, err
		}
		ra := NetlinkRouteAttr{Attr: RtAttr(*a), Value: vbuf[:int(a.Len)-SizeofRtAttr]}
		attrs = append(attrs, ra)
		b = b[alen:]
	}
	return attrs, nil
}

// MakeArchivalRecord parses the NetlinkMessage into a ArchivalRecord.  If skipLocal is true, it will return nil for
// loopback, local unicast, multicast, and unspecified connections.
// Note that Parse does not populate the Timestamp field, so caller should do so.
func MakeSnapShot(msg *NetlinkMessage, skipLocal bool) (*Snapshot, error) {
	if msg.Header.Type != 20 {
		return nil, ErrNotType20
	}

	raw, attrBytes := inetdiag.SplitInetDiagMsg(msg.Data)
	if raw == nil {
		return nil, ErrParseFailed
	}
	if skipLocal {
		idm, err := raw.Parse()
		if err != nil {
			return nil, err
		}

		if isLocal(idm.ID.SrcIP()) || isLocal(idm.ID.DstIP()) {
			return nil, nil
		}
	}

	attrsUnsafe, err := ParseRouteAttr(attrBytes)
	if err != nil {
		return nil, err
	}
	maxAttrType := uint16(0)
	for _, a := range attrsUnsafe {
		t := a.Attr.Type
		if t > maxAttrType {
			maxAttrType = t
		}
	}
	if maxAttrType > 2*inetdiag.INET_DIAG_MAX {
		maxAttrType = 2 * inetdiag.INET_DIAG_MAX
	}
	attributes := make([][]byte, maxAttrType+1, maxAttrType+1)
	for _, a := range attrsUnsafe {
		t := a.Attr.Type
		if t > maxAttrType {
			fmt.Println("Error!! Received RouteAttr with very large Type:", t)
			continue
		}
		if attributes[t] != nil {
			// TODO - add metric so we can alert on these.
			fmt.Println("Parse error - Attribute appears more than once:", t)
		}
		attributes[t] = a.Value
	}
	snp, err := decode(&raw, attributes)
	if err != nil {
		return nil, err
	}
	sockInfo := snp.InetDiagMsg.ID.GetSockID()
	snp.SockInfo = &sockInfo
	return snp, nil
}

func isLocal(addr net.IP) bool {
	return addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
}

// Parse returns the InetDiagMsg itself
// Modified from original to also return attribute data array.
func Parse(raw inetdiag.RawInetDiagMsg) (*inetdiag.InetDiagMsg, error) {
	// TODO - why using rtaAlign on InetDiagMsg ???

	align := rtaAlignOf(int(unsafe.Sizeof(inetdiag.InetDiagMsg{})))
	if len(raw) < align {
		return nil, ErrParseFailed
	}
	return (*inetdiag.InetDiagMsg)(unsafe.Pointer(&raw[0])), nil
}

func decode(rawIDM *inetdiag.RawInetDiagMsg, attributes [][]byte) (*Snapshot, error) {
	var err error
	result := Snapshot{}

	if rawIDM != nil {
		result.InetDiagMsg, err = rawIDM.Parse()
		if err != nil {
			fmt.Println("Error decoding RawIDM:", err)
			return nil, err
		}
	}
	for t, raw := range attributes {
		if raw == nil {
			continue
		}
		rta := RouteAttrValue(raw)
		ok := false
		switch t {
		case inetdiag.INET_DIAG_MEMINFO:
			result.MemInfo, ok = rta.toMemInfo()
		case inetdiag.INET_DIAG_INFO:
			result.TCPInfo, ok = rta.toLinuxTCPInfo()
		case inetdiag.INET_DIAG_VEGASINFO:
			result.VegasInfo, ok = rta.toVegasInfo()
		case inetdiag.INET_DIAG_CONG:
			result.CongestionAlgorithm, ok = rta.CongestionAlgorithm()
		case inetdiag.INET_DIAG_TOS:
			result.TOS, ok = rta.toTOS()
		case inetdiag.INET_DIAG_TCLASS:
			result.TClass, ok = rta.toTCLASS()
		case inetdiag.INET_DIAG_SKMEMINFO:
			result.SocketMem, ok = rta.toSockMemInfo()
		case inetdiag.INET_DIAG_SHUTDOWN:
			result.Shutdown, ok = rta.toShutdown()
		case inetdiag.INET_DIAG_DCTCPINFO:
			result.DCTCPInfo, ok = rta.toDCTCPInfo()
		case inetdiag.INET_DIAG_PROTOCOL:
			result.Protocol, ok = rta.toProtocol()
		case inetdiag.INET_DIAG_MARK:
			result.Mark, ok = rta.toMark()
		case inetdiag.INET_DIAG_BBRINFO:
			result.BBRInfo, ok = rta.toBBRInfo()
		case inetdiag.INET_DIAG_CLASS_ID:
			result.ClassID, ok = rta.toClassID()
		}
		bit := uint32(1) << uint8(t-1)
		result.Observed |= bit
		if !ok {
			result.NotFullyParsed |= bit
		}
	}
	return &result, nil
}

/*********************************************************************************************/
/*          Conversions from RouteAttr.Value to various tcp and inetdiag structs             */
/*********************************************************************************************/

// RouteAttrValue is the type of RouteAttr.Value
type RouteAttrValue []byte

// maybeCopy checks whether the src is the full size of the intended struct size.
// If so, it just returns the pointer, otherwise it copies the content to an
// appropriately sized new byte slice, and returns pointer to that.
func maybeCopy(src []byte, size int, msgType string) (unsafe.Pointer, bool) {
	if len(src) < size {
		data := make([]byte, size)
		copy(data, src)
		return unsafe.Pointer(&data[0]), true
	}
	return unsafe.Pointer(&src[0]), len(src) == size
}

// toMemInfo maps the raw RouteAttrValue onto a MemInfo.
func (raw RouteAttrValue) toMemInfo() (*inetdiag.MemInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.MemInfo{}))
	data, ok := maybeCopy(raw, structSize, "MemInfo")
	if !ok {
		fmt.Println("memInfo data is larger than struct")
	}
	return (*inetdiag.MemInfo)(data), ok
}

// toLinuxTCPInfo maps the raw RouteAttrValue into a LinuxTCPInfo struct.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toLinuxTCPInfo() (*tcp.LinuxTCPInfo, bool) {
	structSize := (int)(unsafe.Sizeof(tcp.LinuxTCPInfo{}))
	data, ok := maybeCopy(raw, structSize, "TCPInfo")
	if !ok {
		fmt.Println("tcpinfo data is larger than struct")
	}
	return (*tcp.LinuxTCPInfo)(data), ok
}

// toVegasInfo maps the raw RouteAttrValue onto a VegasInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toVegasInfo() (*inetdiag.VegasInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.VegasInfo{}))
	data, ok := maybeCopy(raw, structSize, "VegasInfo")
	return (*inetdiag.VegasInfo)(data), ok
}

// CongestionAlgorithm returns the congestion algorithm string
// INET_DIAG_CONG
func (raw RouteAttrValue) CongestionAlgorithm() (string, bool) {
	// This is sometimes empty, but that is valid, so we return true.
	return string(raw[:len(raw)-1]), true
}

func (raw RouteAttrValue) toUint8() (uint8, bool) {
	if len(raw) < 1 {
		return 0, false
	}
	return uint8(raw[0]), true
}

// toTOS marshals the TCP Type Of Service field.  See https://tools.ietf.org/html/rfc3168
func (raw RouteAttrValue) toTOS() (uint8, bool) {
	return raw.toUint8()
}

// toTCLASS marshals the TCP Traffic Class octet.  See https://tools.ietf.org/html/rfc3168
func (raw RouteAttrValue) toTCLASS() (uint8, bool) {
	return raw.toUint8()
}

// toTCLASS marshals the TCP Traffic Class octet.  See https://tools.ietf.org/html/rfc3168
func (raw RouteAttrValue) toClassID() (uint8, bool) {
	return raw.toUint8()
}

// toSockMemInfo maps the raw RouteAttrValue onto a SockMemInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toSockMemInfo() (*inetdiag.SocketMemInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.SocketMemInfo{}))
	data, ok := maybeCopy(raw, structSize, "SockMemInfo")
	return (*inetdiag.SocketMemInfo)(data), ok
}

func (raw RouteAttrValue) toShutdown() (uint8, bool) {
	return raw.toUint8()
}

// toVegasInfo maps the raw RouteAttrValue onto a VegasInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toDCTCPInfo() (*inetdiag.DCTCPInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.DCTCPInfo{}))
	data, ok := maybeCopy(raw, structSize, "DCTCPInfo")
	return (*inetdiag.DCTCPInfo)(data), ok
}

func (raw RouteAttrValue) toProtocol() (inetdiag.Protocol, bool) {
	p, ok := raw.toUint8()
	return inetdiag.Protocol(p), ok
}

func (raw RouteAttrValue) toMark() (uint32, bool) {
	if raw == nil || len(raw) != 4 {
		return 0, false
	}
	return *(*uint32)(unsafe.Pointer(&raw[0])), true
}

// toBBRInfo maps the raw RouteAttrValue onto a BBRInfo.
// For older data, it may have to copy the bytes.
func (raw RouteAttrValue) toBBRInfo() (*inetdiag.BBRInfo, bool) {
	structSize := (int)(unsafe.Sizeof(inetdiag.BBRInfo{}))
	data, ok := maybeCopy(raw, structSize, "BBRInfo")
	return (*inetdiag.BBRInfo)(data), ok
}
