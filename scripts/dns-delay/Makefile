# Copyright 2021 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

REGISTRY ?= gcr.io/gke-release-staging
VERSION ?= 0.0.1
IMAGE := $(REGISTRY)/install-dns-delay

.PHONY: container
container:
	@docker build -t $(IMAGE):$(VERSION) .

.PHONY: push
push: container
	@docker push $(IMAGE):$(VERSION)

.PHONY: version
version:
	@echo $(VERSION)
