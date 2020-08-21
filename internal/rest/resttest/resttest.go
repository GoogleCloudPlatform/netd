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

// Package resttest provides utilities for HTTP mock testing.
package resttest

import "net/http"

type DoFunc func(req *http.Request) (*http.Response, error)

// MockClient allows mocking the Do function
type MockClient struct {
	DoFunc DoFunc
}

func NewMockClient(doFunc DoFunc) *MockClient {
	return &MockClient{
		DoFunc: doFunc,
	}
}

// Do calls MockClient's DoFunc
func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}
