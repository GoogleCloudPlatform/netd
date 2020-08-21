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

// Package ipttest provides utilities for IPTables mock testing.
package ipttest

import (
	"fmt"
	"strings"
)

const (
	AcceptPolicy = "ACCEPT"
	DropPolicy   = "DROP"
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

type FakeIPTable struct {
	Rules    map[string][]string
	Policies map[string]string
}

type FakeIPTables struct {
	Tables map[string]*FakeIPTable
}

func NewFakeIPTable() *FakeIPTable {
	return &FakeIPTable{
		Rules:    make(map[string][]string),
		Policies: make(map[string]string),
	}
}

func NewFakeIPTables(tableNames ...string) *FakeIPTables {
	tables := make(map[string]*FakeIPTable)
	for _, name := range tableNames {
		tables[name] = NewFakeIPTable()
	}
	return &FakeIPTables{
		Tables: tables,
	}
}

func (i FakeIPTables) NewChain(table, chain string) error {
	if _, ok := i.Tables[table].Rules[chain]; ok {
		// Chain already exists
		return NewFakeError(AlreadyExistErr)
	}

	i.Tables[table].Rules[chain] = make([]string, 0, 5)
	// Default chain policy
	i.Tables[table].Policies[chain] = AcceptPolicy
	return nil
}

func (i FakeIPTables) ClearChain(table, chain string) error {
	i.Tables[table].Rules[chain] = make([]string, 0, 5)
	return nil
}
func (i FakeIPTables) DeleteChain(table, chain string) error {
	if _, ok := i.Tables[table].Rules[chain]; !ok {
		// Chain does not exist
		return NewFakeError(NotExistErr)
	}

	delete(i.Tables[table].Rules, chain)
	delete(i.Tables[table].Policies, chain)

	return nil
}

func (i FakeIPTables) List(table, chain string) ([]string, error) {
	if _, ok := i.Tables[table].Rules[chain]; !ok {
		// Chain does not exist
		return nil, NewFakeError(NotExistErr)
	}

	return append([]string{fmt.Sprintf("-P %s %s", chain, i.Tables[table].Policies[chain])}, i.Tables[table].Rules[chain]...), nil
}

func (i FakeIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	if _, ok := i.Tables[table].Rules[chain]; !ok {
		// Chain does not exist
		return NewFakeError(NotExistErr)
	}
	// Valid iptables rules position: 1 to len(chain) + 1
	index := pos - 1
	if index < 0 || pos > len(i.Tables[table].Rules[chain]) {
		return fmt.Errorf("pos out of bounds: %d", pos)
	}

	if index == len(i.Tables[table].Rules[chain]) {
		i.Tables[table].Rules[chain] = append(i.Tables[table].Rules[chain], rule)
	} else {
		i.Tables[table].Rules[chain] = append(i.Tables[table].Rules[chain][:index+1], i.Tables[table].Rules[chain][index:]...)
		i.Tables[table].Rules[chain][index] = rule
	}

	return nil
}

func (i FakeIPTables) AppendUnique(table, chain string, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	for _, r := range i.Tables[table].Rules[chain] {
		if r == rule {
			return nil
		}
	}
	i.Tables[table].Rules[chain] = append(i.Tables[table].Rules[chain], rule)
	return nil
}
func (i FakeIPTables) Delete(table, chain string, rulespec ...string) error {
	rule := strings.Join(rulespec, " ")
	for index, r := range i.Tables[table].Rules[chain] {
		if r == rule {
			i.Tables[table].Rules[chain] = append(i.Tables[table].Rules[chain][:index], i.Tables[table].Rules[chain][index+1:]...)
			return nil
		}
	}

	delete(i.Tables[table].Rules, chain)

	return nil
}
