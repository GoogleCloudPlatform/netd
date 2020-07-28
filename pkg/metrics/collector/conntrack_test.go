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

func TestConntrack(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		desc  string
		input string
		want  conntrackStats
	}{
		{
			desc: "one line of data",
			input: "entries  searched found new invalid ignore delete delete_list insert insert_failed " +
				"drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n" +
				"000005d2  00000000 00000000 00000000 00000002 0047b7ef 00000000 00000000 00000000 " +
				"00000088 0000015 00000000 00000000  00000000 00000000 00000000 00000255\n",
			want: conntrackStats{insertFailed: 136, drop: 21},
		},
		{
			desc: "multiple lines of data",
			input: "entries  searched found new invalid ignore delete delete_list insert insert_failed " +
				"drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n" +
				"000005d2  00000000 00000000 00000000 00000003 00512c38 00000000 00000000 00000000 " +
				"00000000 00000000 00000000 00000000  00000000 00000000 00000000 00000290\n" +
				"000005d2  00000000 00000000 00000000 00000002 0047b7ef 00000000 00000000 00000000 " +
				"00000008 00000005 00000000 00000000  00000000 00000000 00000000 00000255\n" +
				"000005d2  00000000 00000000 00000000 00000003 0042ab82 00000000 00000000 00000000 " +
				"00000010 00000000 00000000 00000000  00000000 00000000 00000000 00000245\n" +
				"000005d2  00000000 00000000 00000000 00000000 00403f1b 00000000 00000000 00000000 " +
				"00000000 00000020 00000000 00000000  00000000 00000000 00000000 0000026d",

			want: conntrackStats{insertFailed: 24, drop: 37},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			stats, err := parseConntrackFile(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("parseConntrackFile(%q) = _, %v, want _, nil", tc.input, err)
			}
			if *stats != tc.want {
				t.Errorf("parseConntrackFile(%q) = %+v, nil, want %+v, nil", tc.input, *stats, tc.want)
			}
		})
	}
}

func TestConntrackInvalidInput(t *testing.T) {
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
			desc:  "missing fields in header",
			input: "entries  searched found new invalid",
		},
		{
			desc: "header only, no data",
			input: "entries  searched found new invalid ignore delete delete_list insert insert_failed " +
				"drop early_drop icmp_error  expect_new expect_create expect_delete search_restart",
		},
		{
			desc: "missing fields in data",
			input: "entries  searched found new invalid ignore delete delete_list insert insert_failed " +
				"drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n" +
				"000005d2  00000000 00000000 00000000 00000003 00512c38 00000000 00000000 00000000 " +
				"00000000 00000000 00000000 00000000  00000000 00000000 00000000 00000290\n" +
				"000005d2  00000000 00000000 00000002 0047b7ef 00000000 00000000 00000000 00000008 " +
				"00000005 00000000 00000000  00000000 00000000 00000000 00000255",
		},
		{
			desc: "wrong field in data",
			input: "entries  searched found new invalid ignore delete delete_list insert insert_failed " +
				"drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n" +
				"000005d2  00000000 00000000 00000000 00000003 00512c38 00000000 00000000 00000000 " +
				"00000000 00000000 00000000 00000000  00000000 00000000 00000000 00000290\n" +
				"000005d2  00000000 00000000 00000000 00000002 0047b7ef 00000000 00000000 00000000 " +
				"00000008 f00000005 00000000 00000000  00000000 00000000 00000000 00000255",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := parseConntrackFile(strings.NewReader(tc.input))
			if err == nil {
				t.Errorf("parseConntrackFile(%q) = _, nil, want error", tc.input)
			}
		})
	}
}
