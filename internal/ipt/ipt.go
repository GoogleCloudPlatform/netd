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

// Package ipt defines the iptables interfaces.
package ipt

import (
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
)

var (
	IPv4Tables *iptables.IPTables
	IPv6Tables *iptables.IPTables
)

func init() {
	var err error
	if IPv4Tables, err = iptables.NewWithProtocol(iptables.ProtocolIPv4); err != nil {
		glog.Errorf("failed to initialize iptables: %v", err)
	}
	if IPv6Tables, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil {
		glog.Errorf("failed to initialize ip6tables: %v", err)
	}
}

type Error interface {
	ExitStatus() int
	IsNotExist() bool
}

type IPTabler interface {
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
	DeleteChain(table, chain string) error
	List(table, chain string) ([]string, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
}

// IPTablesRule defines an iptables rule
type IPTablesRule []string

// IPTablesSpec defines iptables rules and the associated table and chain
type IPTablesSpec struct {
	TableName string
	ChainName string
	Rules     []IPTablesRule
	IPT       IPTabler
}
