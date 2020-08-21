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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GoogleCloudPlatform/netd/internal/ipt"
)

func TestFakeIPTables(t *testing.T) {
	fakeIPT := NewFakeIPTables("table")

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
	assert.Len(t, fakeIPT.Tables["table"].Rules["chain"], 2)

	rulesList, err := fakeIPT.List("table", "chain")
	assert.NoError(t, err)
	expectedList := []string{"-P chain ACCEPT", "rule1", "rule2"}
	assert.Equal(t, expectedList, rulesList)

	pos := 0
	assert.EqualError(t, fakeIPT.Insert("table", "chain", pos, "inserted", "rule1"), fmt.Sprintf("pos out of bounds: %d", pos))
	pos = len(fakeIPT.Tables["table"].Rules["chain"]) + 1
	assert.EqualError(t, fakeIPT.Insert("table", "chain", pos, "inserted", "rule1"), fmt.Sprintf("pos out of bounds: %d", pos))
	pos = 1
	assert.NoError(t, fakeIPT.Insert("table", "chain", pos, "inserted", "rule1"))
	assert.Len(t, fakeIPT.Tables["table"].Rules["chain"], 3)
	pos = 2
	assert.NoError(t, fakeIPT.Insert("table", "chain", pos, "inserted", "rule2"))
	assert.Len(t, fakeIPT.Tables["table"].Rules["chain"], 4)
	pos = len(fakeIPT.Tables["table"].Rules["chain"])
	assert.NoError(t, fakeIPT.Insert("table", "chain", pos, "inserted", "rule3"))
	assert.Len(t, fakeIPT.Tables["table"].Rules["chain"], 5)

	fakeIPT.Delete("table", "chain", "rule1")
	assert.Len(t, fakeIPT.Tables["table"].Rules["chain"], 4)

	fakeIPT.ClearChain("table", "chain")
	assert.Len(t, fakeIPT.Tables["table"].Rules["chain"], 0)

	assert.NoError(t, fakeIPT.DeleteChain("table", "chain"))
	assert.Empty(t, fakeIPT.Tables["table"].Rules)
	assert.Empty(t, fakeIPT.Tables["table"].Policies)

	// Trying to delete a nonexistent chain should return an error with exitStatus == NotExistErr
	if err := fakeIPT.DeleteChain("table", "chain"); err != nil {
		if eerr, eok := err.(ipt.Error); eok {
			assert.Equal(t, eerr.ExitStatus(), NotExistErr)
		} else {
			t.Fatalf("Unable to assert error to ipt.Error: %v", err)
		}
	}

}
