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
	"testing"
)

// Tests if got contains all of want.
func mapContainsAll(got, want map[string]uint64) bool {
	for k, v := range want {
		if _, ok := got[k]; ok && v == got[k] {
			continue
		}
		return false
	}
	return true
}

func TestParseNetstat(t *testing.T) {
	t.Parallel()

	fakeNetstat := `
TcpExt: SyncookiesSent RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps TcpTimeoutRehash TcpDuplicateDataRehash TCPDSACKRecvSegs TCPDSACKIgnoredDubious
TcpExt: 0 0 0 0 0 440 99 21800 3`
	want := map[string]uint64{"TcpTimeoutRehash": 440, "TcpDuplicateDataRehash": 99}
	got, err := parseKeyValueLines(fakeNetstat, netstatLabel)
	if err != nil {
		t.Errorf("failed parseNetstat, got %q", err)
	}
	if !mapContainsAll(got, want) {
		t.Errorf("parseNetstatVals returns %+q, want %+q", got, want)
	}
}

func TestParseSnmp(t *testing.T) {
	t.Parallel()
	fakeSnmp := `
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 -2 3 4 5 6 7 8 9 10 11 12 13 14 15
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
Udp: 0 0 0 0 0 0 0 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
UdpLite: 0 0 0 0 0 0 0 0`
	want := map[string]uint64{"OutSegs": 11, "InSegs": 10, "RetransSegs": 12}
	got, err := parseKeyValueLines(fakeSnmp, snmpLabel)
	if err != nil {
		t.Errorf("failed parseNetstat, got %q", err)
	}
	if !mapContainsAll(got, want) {
		t.Errorf("parseSnmpVals returns %+q, want %+q", got, want)
	}

}
