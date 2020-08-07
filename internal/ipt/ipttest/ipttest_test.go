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

package ipttest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
)

func TestFakeIPTables(t *testing.T) {
	fakeIPT := NewFakeIPTables()

	assert.NoError(t, fakeIPT.NewChain("table", "chain"))
	// Trying to create an already existent chain should return an error with exitStatus == AlreadyExistErr
	if err := fakeIPT.NewChain("table", "chain"); err != nil {
		if eerr, eok := err.(ipt.Error); eok {
			assert.Equal(t, eerr.ExitStatus(), AlreadyExistErr)
		} else {
			t.Fatalf("Unable to assert error to ipt.Error: %v", err)
		}
	}

	fakeIPT.AppendUnique("table", "chain", "rule1")
	fakeIPT.AppendUnique("table", "chain", "rule1")
	fakeIPT.AppendUnique("table", "chain", "rule2")

	if len(fakeIPT.IPTCache["chain"]) != 2 {
		t.Error("fakeIPT['chain'] should contain 2 rules")
	}

	fakeIPT.Delete("table", "chain", "rule1")
	if len(fakeIPT.IPTCache["chain"]) != 1 {
		t.Error("fakeIPT['chain'] should contain 1 rules")
	}

	fakeIPT.ClearChain("table", "chain")
	if len(fakeIPT.IPTCache["chain"]) != 0 {
		t.Error("fakeIPT['chain'] should be empty")
	}

	assert.NoError(t, fakeIPT.DeleteChain("table", "chain"))
	if len(fakeIPT.IPTCache) != 0 {
		t.Error("fakeIPT should be empty")
	}
	// Trying to delete a nonexistent chain should return an error with exitStatus == NotExistErr
	if err := fakeIPT.DeleteChain("table", "chain"); err != nil {
		if eerr, eok := err.(ipt.Error); eok {
			assert.Equal(t, eerr.ExitStatus(), NotExistErr)
		} else {
			t.Fatalf("Unable to assert error to ipt.Error: %v", err)
		}
	}

}
