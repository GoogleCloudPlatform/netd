package tcp_test

import (
	"testing"

	"github.com/GoogleCloudPlatform/netd/pkg/tcp_metrics/tcp"
)

// TODO - sanity checks against syscall structs?

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
