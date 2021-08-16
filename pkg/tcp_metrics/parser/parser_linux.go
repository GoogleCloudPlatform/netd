// Package netlink contains the bare minimum needed to partially parse netlink messages.
package parser

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Error types.
var (
	ErrNotType20   = errors.New("NetlinkMessage wrong type")
	ErrParseFailed = errors.New("Unable to parse InetDiagMsg")
)

// TODO - get these from sys/unix or syscall
const (
	RTA_ALIGNTO    = 4
	SizeofNlMsghdr = 0x10
	SizeofNlAttr   = 0x4
	SizeofRtAttr   = 0x4

	EINVAL = syscall.Errno(0x16)
)

// TODO use unix instead.
type NlMsghdr = syscall.NlMsghdr
type NetlinkMessage = syscall.NetlinkMessage
type RtAttr = syscall.RtAttr
type NetlinkRouteAttr = syscall.NetlinkRouteAttr

/*********************************************************************************************
*                         Low level netlink message stuff
*********************************************************************************************/
// rtaAlignOf rounds the length of a netlink route attribute up to align it properly.
func rtaAlignOf(attrlen int) int {
	return (attrlen + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func netlinkRouteAttrAndValue(b []byte) (*unix.RtAttr, []byte, int, error) {
	a := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
	if int(a.Len) < unix.SizeofRtAttr || int(a.Len) > len(b) {
		return nil, nil, 0, unix.EINVAL
	}
	return a, b[unix.SizeofRtAttr:], rtaAlignOf(int(a.Len)), nil
}
