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

// Package iptest provides utilities for IPTables mock testing.
package ipttest

import (
	"strings"
)

const (
	AlreadyExistErr = iota + 1
	NotExistErr
)

type FakeError struct {
	exitStatus int
}

func NewFakeError(exitStatus int) *FakeError {
	return &FakeError{
		exitStatus: exitStatus,
	}
}

func (e *FakeError) Error() string {
	return ""
}

func (e *FakeError) ExitStatus() int {
	return e.exitStatus
}

func (e *FakeError) IsNotExist() bool {
	return e.exitStatus == NotExistErr
}

type FakeIPTables struct {
	IPTCache map[string][]string
}

func NewFakeIPTables() *FakeIPTables {
	return &FakeIPTables{
		IPTCache: make(map[string][]string),
	}
}

func (i FakeIPTables) NewChain(table, chain string) error {
	if _, ok := i.IPTCache[chain]; ok {
		// Chain already exists
		return NewFakeError(AlreadyExistErr)
	}

	i.IPTCache[chain] = make([]string, 0, 5)
	return nil
}

func (i FakeIPTables) ClearChain(table, chain string) error {
	i.IPTCache[chain] = make([]string, 0, 5)
	return nil
}
func (i FakeIPTables) DeleteChain(table, chain string) error {
	if _, ok := i.IPTCache[chain]; !ok {
		// Chain does not exist
		return NewFakeError(NotExistErr)
	}

	delete(i.IPTCache, chain)
	return nil
}

func (i FakeIPTables) AppendUnique(table, chain string, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	for _, r := range i.IPTCache[chain] {
		if r == rule {
			return nil
		}
	}
	i.IPTCache[chain] = append(i.IPTCache[chain], rule)
	return nil
}
func (i FakeIPTables) Delete(table, chain string, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	for index, r := range i.IPTCache[chain] {
		if r == rule {
			i.IPTCache[chain] = append(i.IPTCache[chain][:index], i.IPTCache[chain][index+1:]...)
			return nil
		}
	}
	return nil
}
