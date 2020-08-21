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
	"io/ioutil"
	"path"
	"strconv"
	"strings"
)

var procPath string

// readUintFromFile reads a uint from file given by path. The file is supposed to only contain a single uint
// in base 10. Otherwise, an error will be returned.
func readUintFromFile(path string) (uint64, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

// procFilePath returns the full path of a proc file given the proc file name
func procFilePath(name string) string {
	return path.Join(procPath, name)
}
