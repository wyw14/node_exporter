// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"testing"
)

func TestDeviceFilter(t *testing.T) {
	tests := []struct {
		ignore         string
		accept         string
		name           string
		expectedResult bool
	}{
		{"", "", "eth0", false},
		{"", "^💩0$", "💩0", false},
		{"", "^💩0$", "💩1", true},
		{"", "^💩0$", "veth0", true},
		{"^💩", "", "💩3", true},
		{"^💩", "", "veth0", false},
	}

	for _, test := range tests {
		filter, err := newDeviceFilter(test.ignore, test.accept)
		if err != nil {
			t.Fatalf("unexpected error compiling filter (ignore=%q accept=%q): %v", test.ignore, test.accept, err)
		}
		result := filter.ignored(test.name)

		if result != test.expectedResult {
			t.Errorf("ignorePattern=%v acceptPattern=%v ifname=%v expected=%v result=%v", test.ignore, test.accept, test.name, test.expectedResult, result)
		}
	}
}

func TestNewDeviceFilterInvalidRegexp(t *testing.T) {
	// A malformed regular expression must be reported as an error instead of
	// panicking, so that a bad flag value can never crash the exporter.
	tests := []struct {
		name   string
		ignore string
		accept string
	}{
		{name: "invalid exclude", ignore: "["},
		{name: "invalid include", accept: "("},
		{name: "both invalid", ignore: "foo[", accept: "bar("},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("newDeviceFilter panicked on invalid pattern: %v", r)
				}
			}()
			if _, err := newDeviceFilter(tt.ignore, tt.accept); err == nil {
				t.Fatalf("expected an error for ignore=%q accept=%q, got nil", tt.ignore, tt.accept)
			}
		})
	}
}
