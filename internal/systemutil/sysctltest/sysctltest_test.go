/*
Copyright 2020 Google Inc.

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

package sysctltest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFakeSysctl(t *testing.T) {
	fakeSysctl := FakeSysctl{"existent.key": "0"}

	getSysctl(t, "0", fakeSysctl, "existent.key")

	key := "nonexistent.key"
	v, err := fakeSysctl.Sysctl(key)
	assert.EqualError(t, err, fmt.Sprintf("invalid key: %s", key))
	assert.Empty(t, v)

	key = "nonexistent.key"
	v, err = fakeSysctl.Sysctl(key, "1", "2")
	assert.EqualError(t, err, "unexcepted additional parameters")
	assert.Empty(t, v)

	setSysctl(t, fakeSysctl, "key1", "1")
	setSysctl(t, fakeSysctl, "key2", "2")
	setSysctl(t, fakeSysctl, "key1", "3")

	getSysctl(t, "3", fakeSysctl, "key1")
	getSysctl(t, "2", fakeSysctl, "key2")

	key = "key1"
	v, err = fakeSysctl.Sysctl(key, "1", "2")
	assert.EqualError(t, err, "unexcepted additional parameters")
	assert.Empty(t, v)

	assert.Len(t, fakeSysctl, 3)
}

func setSysctl(t *testing.T, fakeSysctl FakeSysctl, key, val string) {
	t.Helper()
	v, err := fakeSysctl.Sysctl(key, val)
	assert.NoError(t, err)
	assert.Equal(t, val, v)
}

func getSysctl(t *testing.T, expectedVal string, fakeSysctl FakeSysctl, key string) {
	t.Helper()
	v, err := fakeSysctl.Sysctl(key)
	assert.NoError(t, err)
	assert.Equal(t, expectedVal, v)
}
