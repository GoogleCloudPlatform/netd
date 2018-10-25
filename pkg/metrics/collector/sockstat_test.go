/*
Copyright 2018 Google Inc.

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
	"strings"
	"testing"
)

func TestSockstats(t *testing.T) {
	t.Parallel()
	in := []string{
		"sockets: used 270\n" +
			"TCP: inuse 23 orphan 0 tw 10 alloc 52 mem 6\n" +
			"UDP: inuse 3 mem 3\n" +
			"UDPLITE: inuse 0\n" +
			"RAW: inuse 0\n" +
			"FRAG: inuse 0 memory 0",
		"TCP6: inuse 14\n" +
			"UDP6: inuse 1\n" +
			"UDPLITE6: inuse 0\n" +
			"RAW6: inuse 0\n" +
			"FRAG6: inuse 0 memory 0",
	}

	want := socketStats{tcpInUse: 37, udpInUse: 4, tcpTimeWait: 10, memUsedInPages: 9}

	ss, err := parseSockStats(strings.NewReader(in[0]))
	if err != nil {
		t.Fatalf("parseSockStats = _, %v, want _, nil", err)
	}

	ss6, _ := parseSockStats(strings.NewReader(in[1]))
	if err != nil {
		t.Fatalf("parseSockStats = _, %v, want _, nil", err)
	}

	ss.merge(ss6)
	if *ss != want {
		t.Errorf("parseSockStats(%q) returns %+v, want %+v", in, *ss, want)
	}
}

func TestSockstatsInvalidInput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		desc  string
		input string
	}{
		{
			desc:  "empty file",
			input: "",
		},
		{
			desc:  "empty line",
			input: " ",
		},
		{
			desc:  "missing value",
			input: "TCP:",
		},
		{
			desc:  "wrong format",
			input: "TCP inuse 23",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := parseSockStats(strings.NewReader(tc.input))
			if err == nil {
				t.Errorf("parseSockStats(%q) = _, nil, want error", tc.input)
			}
		})
	}
}
