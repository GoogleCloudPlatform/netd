package tcp_test

import (
	"testing"
	"unsafe"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/tcp"
	"golang.org/x/sys/unix"
)

func TestLinuxTCPInfoSize(t *testing.T) {
	// This test checks if the size of our tcp.LinuxTCPInfo struct
	// matches the size of the kernel's tcp_info struct from x/sys/unix.
	// A mismatch can cause issues when parsing netlink messages.
	var want = unsafe.Sizeof(unix.TCPInfo{})
	var got = unsafe.Sizeof(tcp.LinuxTCPInfo{})
	if got != want {
		t.Errorf("sizeof(tcp.LinuxTCPInfo) = %d, want sizeof(unix.TCPInfo) = %d", got, want)
	}
}

func TestState_String(t *testing.T) {
	tests := []struct {
		in   tcp.State
		want string
	}{
		{tcp.INVALID, "INVALID"},
		{tcp.ESTABLISHED, "ESTABLISHED"},
		{tcp.SYN_SENT, "SYN_SENT"},
		{tcp.SYN_RECV, "SYN_RECV"},
		{tcp.FIN_WAIT1, "FIN_WAIT1"},
		{tcp.FIN_WAIT2, "FIN_WAIT2"},
		{tcp.TIME_WAIT, "TIME_WAIT"},
		{tcp.CLOSE, "CLOSE"},
		{tcp.CLOSE_WAIT, "CLOSE_WAIT"},
		{tcp.LAST_ACK, "LAST_ACK"},
		{tcp.LISTEN, "LISTEN"},
		{tcp.CLOSING, "CLOSING"},
		{tcp.State(99), "UNKNOWN_STATE_99"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("State.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
