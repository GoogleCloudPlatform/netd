package inetdiag

/*
There should be a corresponding struct for every element of this enum
defined in uapi/linux/inet_diag.h

	INET_DIAG_MEMINFO
	INET_DIAG_INFO  // This one is in tcp.go
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
*/

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"unsafe"
)

// Constants from linux.
const (
	SOCK_DIAG_BY_FAMILY = 20 // uapi/linux/sock_diag.h
)

var (
	// ErrBadPid is used when the PID is mismatched between the netlink socket and the calling process.
	ErrBadPid = errors.New("bad PID, can't listen to NL socket")

	// ErrBadSequence is used when the Netlink response has a bad sequence number.
	ErrBadSequence = errors.New("bad sequence number, can't interpret NetLink response")

	// ErrBadMsgData is used when the NHetlink response has bad or missing data.
	ErrBadMsgData = errors.New("bad message data from netlink message")
)

// ReqV2 is the Netlink request struct, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type ReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	ID            LinuxSockID
}

// SizeofReqV2 is the size of the struct.
// TODO should we just make this explicit in the code?
const SizeofReqV2 = int(unsafe.Sizeof(ReqV2{})) // Should be 0x38

// Serialize is provided for json serialization?
// TODO - should use binary functions instead?
func (req *ReqV2) Serialize() []byte {
	return (*(*[SizeofReqV2]byte)(unsafe.Pointer(req)))[:]
}

// Len is provided for json serialization?
func (req *ReqV2) Len() int {
	return SizeofReqV2
}

// NewReqV2 creates a new request.
func NewReqV2(family, protocol uint8, states uint32) *ReqV2 {
	return &ReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		IDiagStates:   states,
	}
}

// Types for LinuxSockID fields.
type cookieType [8]byte

// TODO - remove all these.
func (c *cookieType) MarshalCSV() (string, error) {
	value := binary.LittleEndian.Uint64(c[:])
	return fmt.Sprintf("%X", value), nil
}

type ipType [16]byte

func (ipAddr *ipType) Marshal() (string, error) {
	netIP := ip(*ipAddr)
	return netIP.String(), nil
}

// Port encodes a LinuxSockID Port
type Port [2]byte

func (p *Port) Marshal() (string, error) {
	value := binary.BigEndian.Uint16(p[:])
	return fmt.Sprintf("%d", value), nil
}

// Interface encodes the LinuxSockID Interface field.
type netIF [4]byte

func (nif *netIF) Marshal() (string, error) {
	value := binary.BigEndian.Uint32(nif[:])
	return fmt.Sprintf("%d", value), nil
}

// LinuxSockID is the binary linux representation of a socket, as in linux/inet_diag.h
// Linux code comments indicate this struct uses the network byte order!!!
// All fields are ignored for bigquery, and handled in code.
// TODO make this unexported
type LinuxSockID struct {
	IDiagSPort  Port
	IDiagDPort  Port
	IDiagSrc    ipType
	IDiagDst    ipType
	IDiagIf     netIF
	IDiagCookie cookieType
}

// SockID is the natural golang struct equivalent of LinuxSockID
type SockID struct {
	SPort     uint16
	DPort     uint16
	SrcIP     string
	DstIP     string
	Interface uint32
	Cookie    uint64
}

// GetSockID extracts the SockID from the LinuxSockID.
func (id *LinuxSockID) GetSockID() SockID {
	sid := SockID{
		SrcIP:     id.SrcIP().String(),
		SPort:     id.SPort(),
		DstIP:     id.DstIP().String(),
		DPort:     id.DPort(),
		Interface: id.Interface(),
		Cookie:    id.Cookie(),
	}
	return sid
}

// Interface returns the interface number.
func (id *LinuxSockID) Interface() uint32 {
	return binary.BigEndian.Uint32(id.IDiagIf[:])
}

// SrcIP returns a golang net encoding of source address.
func (id *LinuxSockID) SrcIP() net.IP {
	return ip(id.IDiagSrc)
}

// DstIP returns a golang net encoding of destination address.
func (id *LinuxSockID) DstIP() net.IP {
	return ip(id.IDiagDst)
}

// SPort returns the host byte ordered port.
// In general, Netlink is supposed to use host byte order, but this seems to be an exception.
// Perhaps Netlink is reading a tcp stack structure that holds the port in network byte order.
func (id *LinuxSockID) SPort() uint16 {
	return binary.BigEndian.Uint16(id.IDiagSPort[:])
}

// DPort returns the host byte ordered port.
// In general, Netlink is supposed to use host byte order, but this seems to be an exception.
// Perhaps Netlink is reading a tcp stack structure that holds the port in network byte order.
func (id *LinuxSockID) DPort() uint16 {
	return binary.BigEndian.Uint16(id.IDiagDPort[:])
}

// Cookie returns the LinuxSockID's 64 bit unsigned cookie.
func (id *LinuxSockID) Cookie() uint64 {
	// This is a socket UUID generated within the kernel, and is therefore in host byte order.
	return binary.LittleEndian.Uint64(id.IDiagCookie[:])
}

// TODO should use more net.IP code instead of custom code.
// TODO: reconcile this encoding of v4-in-v6 with the encoding used in https://golang.org/src/net/ip.go?s=1216:1245#L35
func ip(bytes [16]byte) net.IP {
	if isIpv6(bytes) {
		return ipv6(bytes)
	}
	return ipv4(bytes)
}

func isIpv6(original [16]byte) bool {
	for i := 4; i < 16; i++ {
		if original[i] != 0 {
			return true
		}
	}
	return false
}

func ipv4(original [16]byte) net.IP {
	return net.IPv4(original[0], original[1], original[2], original[3]).To4()
}

func ipv6(original [16]byte) net.IP {
	return original[:]
}

// HostCond is related to filters.  We don't currently use filters, so we don't actually use this type.
type HostCond struct { // inet_diag_hostcond
	Family    uint8  // __u8 family
	PrefixLen uint8  // __u8 prefix_len
	Port      uint16 // int port
	Addr      uint32 // __be32	addr[0];
}

// MarkCond is related to filters.  We don't currently use filters, so we don't actually use this type.
type MarkCond struct { // inet_diag_markcond
	Mark uint32
	Mask uint32
}

// InetDiagMsg is the linux binary representation of a InetDiag message header, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering, unless NLA_F_NET_BYTEORDER flag is present.
type InetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	ID           LinuxSockID
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUID     uint32
	IDiagInode   uint32
}

const (
	// RTA_ALIGNTO previously came from syscall, but explicit here to work on Darwin.
	RTA_ALIGNTO = 4
)

// rtaAlignOf rounds the length of a netlink route attribute up to align it properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + RTA_ALIGNTO - 1) & ^(RTA_ALIGNTO - 1)
}

// RawInetDiagMsg holds the []byte representation of an InetDiagMsg
type RawInetDiagMsg []byte

// SplitInetDiagMsg pulls the InetDiagMsg out, and returns the msg and the remaining data slice.
func SplitInetDiagMsg(data []byte) (RawInetDiagMsg, []byte) {
	// TODO - why using rtaAlign on InetDiagMsg ???
	align := rtaAlignOf(int(unsafe.Sizeof(InetDiagMsg{})))
	if len(data) < align {
		fmt.Println("Wrong length", len(data), "<", align)
		_, file, line, _ := runtime.Caller(2)
		fmt.Println(file, line, data)
		return nil, nil
	}
	return RawInetDiagMsg(data[:align]), data[align:]
}

// ErrParseFailed is returned if InetDiagMsg parsing fails.
var ErrParseFailed = errors.New("Unable to parse InetDiagMsg")

// Parse returns the InetDiagMsg itself
// Modified from original to also return attribute data array.
func (raw RawInetDiagMsg) Parse() (*InetDiagMsg, error) {
	// TODO - why using rtaAlign on InetDiagMsg ???

	align := rtaAlignOf(int(unsafe.Sizeof(InetDiagMsg{})))
	if len(raw) < align {
		return nil, ErrParseFailed
	}
	return (*InetDiagMsg)(unsafe.Pointer(&raw[0])), nil
}

// ErrUnknownAF is returned when the InetDiagMsg.IDiagFamily is unknown.
var ErrUnknownAF = errors.New("unknown address family")

// SocketMemInfo implements the struct associated with INET_DIAG_SKMEMINFO
// Haven't found a corresponding linux struct, but the message is described
// in https://manpages.debian.org/stretch/manpages/sock_diag.7.en.html
type SocketMemInfo struct {
	RmemAlloc  uint32
	Rcvbuf     uint32
	WmemAlloc  uint32
	Sndbuf     uint32
	FwdAlloc   uint32
	WmemQueued uint32
	Optmem     uint32
	Backlog    uint32
	Drops      uint32
}

// MemInfo implements the struct associated with INET_DIAG_MEMINFO, corresponding with
// linux struct inet_diag_meminfo in uapi/linux/inet_diag.h.
type MemInfo struct {
	Rmem uint32
	Wmem uint32
	Fmem uint32
	Tmem uint32
}

// VegasInfo implements the struct associated with INET_DIAG_VEGASINFO, corresponding with
// linux struct tcpvegas_info in uapi/linux/inet_diag.h.
type VegasInfo struct {
	Enabled  uint32
	RTTCount uint32
	RTT      uint32
	MinRTT   uint32
}

// DCTCPInfo implements the struct associated with INET_DIAG_DCTCPINFO attribute, corresponding with
// linux struct tcp_dctcp_info in uapi/linux/inet_diag.h.
type DCTCPInfo struct {
	Enabled uint16
	CEState uint16
	Alpha   uint32
	ABEcn   uint32
	ABTot   uint32
}

// BBRInfo implements the struct associated with INET_DIAG_BBRINFO attribute, corresponding with
// linux struct tcp_bbr_info in uapi/linux/inet_diag.h.
type BBRInfo struct {
	BW         int64
	MinRTT     uint32
	PacingGain uint32
	CwndGain   uint32
}

// LOCALS and PEERS contain an array of sockaddr_storage elements.
/* ss.c parses these elements like this:
static const char *format_host_sa(struct sockaddr_storage *sa)
{
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *saddr = (void *)sa;

	switch (sa->ss_family) {
	case AF_INET:
		return format_host(AF_INET, 4, &saddr->sin.sin_addr);
	case AF_INET6:
		return format_host(AF_INET6, 16, &saddr->sin6.sin6_addr);
	default:
		return "";
	}
}

	INET_DIAG_LOCALS
if (tb[INET_DIAG_LOCALS]) {
	len = RTA_PAYLOAD(tb[INET_DIAG_LOCALS]);
	sa = RTA_DATA(tb[INET_DIAG_LOCALS]);

	printf("locals:%s", format_host_sa(sa));
	for (sa++, len -= sizeof(*sa); len > 0; sa++, len -= sizeof(*sa))
		printf(",%s", format_host_sa(sa));

}
	INET_DIAG_PEERS
if (tb[INET_DIAG_PEERS]) {
	len = RTA_PAYLOAD(tb[INET_DIAG_PEERS]);
	sa = RTA_DATA(tb[INET_DIAG_PEERS]);

	printf(" peers:%s", format_host_sa(sa));
	for (sa++, len -= sizeof(*sa); len > 0; sa++, len -= sizeof(*sa))
		printf(",%s", format_host_sa(sa));
}
*/
