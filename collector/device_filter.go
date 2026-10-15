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
	"fmt"
	"regexp"
)

type deviceFilter struct {
	ignorePattern *regexp.Regexp
	acceptPattern *regexp.Regexp
}

// newDeviceFilter compiles the given exclude/include regular expressions.
// It returns an error instead of panicking on an invalid pattern so that a
// malformed flag value is reported cleanly during collector construction and
// can never crash a running exporter.
func newDeviceFilter(ignoredPattern, acceptPattern string) (deviceFilter, error) {
	var f deviceFilter

	if ignoredPattern != "" {
		pattern, err := regexp.Compile(ignoredPattern)
		if err != nil {
			return deviceFilter{}, fmt.Errorf("invalid exclude regular expression %q: %w", ignoredPattern, err)
		}
		f.ignorePattern = pattern
	}

	if acceptPattern != "" {
		pattern, err := regexp.Compile(acceptPattern)
		if err != nil {
			return deviceFilter{}, fmt.Errorf("invalid include regular expression %q: %w", acceptPattern, err)
		}
		f.acceptPattern = pattern
	}

	return f, nil
}

// ignored returns whether the device should be ignored
func (f *deviceFilter) ignored(name string) bool {
	return (f.ignorePattern != nil && f.ignorePattern.MatchString(name)) ||
		(f.acceptPattern != nil && !f.acceptPattern.MatchString(name))
}
