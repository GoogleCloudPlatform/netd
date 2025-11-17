/*
Copyright 2025 Google Inc.

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

func TestParseIPLocalPortRange(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedMin uint64
		expectedMax uint64
		expectError bool
	}{
		{
			name:        "default range",
			input:       "32768\t60999",
			expectedMin: 32768,
			expectedMax: 60999,
			expectError: false,
		},
		{
			name:        "custom range with spaces",
			input:       "1024 65535",
			expectedMin: 1024,
			expectedMax: 65535,
			expectError: false,
		},
		{
			name:        "range with newline",
			input:       "32768\t60999\n",
			expectedMin: 32768,
			expectedMax: 60999,
			expectError: false,
		},
		{
			name:        "invalid - single value",
			input:       "32768",
			expectError: true,
		},
		{
			name:        "invalid - too many values",
			input:       "32768 60999 65535",
			expectError: true,
		},
		{
			name:        "invalid - non-numeric",
			input:       "abc def",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			min, max, err := parseIPLocalPortRange(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if min != tt.expectedMin {
				t.Errorf("min: got %d, want %d", min, tt.expectedMin)
			}
			if max != tt.expectedMax {
				t.Errorf("max: got %d, want %d", max, tt.expectedMax)
			}
		})
	}
}
