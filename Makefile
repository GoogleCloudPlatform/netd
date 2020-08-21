# Copyright 2018 The Kubernetes Authors.
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

# TODO refactor Makefile to build multiple binaries https://github.com/thockin/go-build-template/blob/master/Makefile
# The binary to build (just the basename).
BIN := netd

# This repo's root import path (under GOPATH).
PKG := github.com/GoogleCloudPlatform/netd

# Where to push the docker image.
# REGISTRY ?= gcr.io/gke-release
REGISTRY ?= gcr.io/gke-release-staging


# Which architecture to build - see $(ALL_ARCH) for options.
ARCH ?= amd64

# This version-strategy uses git tags to set the version string
VERSION ?= $(shell git describe --tags --always --dirty)
#
# This version-strategy uses a manual value to set the version string
# VERSION := 1.2.3

GOLANGCI_LINT_VERSION := v1.30.0

###
### These variables should not need tweaking.
###

SRC_DIRS := cmd pkg internal # directories which hold app source (not vendored)

ALL_ARCH := amd64 arm arm64 ppc64le

# Set default base image dynamically for each arch
ifeq ($(ARCH), amd64)
    BASE_IMAGE ?= alpine
endif
ifeq ($(ARCH), arm)
    BASE_IMAGE ?= armel/busybox
endif
ifeq ($(ARCH), arm64)
    BASE_IMAGE ?= aarch64/busybox
endif
ifeq ($(ARCH), ppc64le)
    BASE_IMAGE ?= ppc64le/busybox
endif

IMAGE := $(REGISTRY)/$(BIN)-$(ARCH)

BUILD_IMAGE ?= golang:1.14-alpine

# Docker run command prefix for containerized build environment
# Any target that runs this command must also run `init` as a prerequisite rule
# to ensure the directories specified in $(BUILD_DIRS) are created
DOCKER_RUN = docker run                                                               \
				--rm                                                                  \
				-u $$(id -u):$$(id -g)                                                \
				-v "$(CURDIR)/.go/.cache:/.cache"                                     \
				-v "$(CURDIR)/.go:/go"                                                \
				-v "$(CURDIR):/go/src/$(PKG)"                                         \
				-v "$(CURDIR)/bin/$(ARCH):/go/bin"                                    \
				-v "$(CURDIR)/bin/$(ARCH):/go/bin/$$(go env GOOS)_$(ARCH)"            \
				-v "$(CURDIR)/.go/std/$(ARCH):/usr/local/go/pkg/linux_$(ARCH)_static" \
				-w "/go/src/$(PKG)"                                                   \
				$(BUILD_IMAGE)

BUILD_DIRS := bin/$(ARCH) .go/src/$(PKG) .go/.cache .go/pkg .go/bin .go/std/$(ARCH)

.PHONY: all
all: init build

# If you want to build all binaries, see the 'all-build' rule.
# If you want to build all containers, see the 'all-container' rule.
# If you want to build AND push all containers, see the 'all-push' rule.
BUILD_ALL_ARCH = $(addprefix build-, $(ALL_ARCH))
CONTAINER_ALL_ARCH = $(addprefix container-, $(ALL_ARCH))
PUSH_ALL_ARCH = $(addprefix push-, $(ALL_ARCH))

.PHONY: all-build $(BUILD_ALL_ARCH)
all-build: $(BUILD_ALL_ARCH)

.PHONY: all-container $(CONTAINER_ALL_ARCH)
all-container: $(CONTAINER_ALL_ARCH)

.PHONY: all-push $(PUSH_ALL_ARCH)
all-push: $(PUSH_ALL_ARCH)

$(BUILD_ALL_ARCH): build-%:
	@$(MAKE) --no-print-directory ARCH=$* build

$(CONTAINER_ALL_ARCH): container-%:
	@$(MAKE) --no-print-directory ARCH=$* container

$(PUSH_ALL_ARCH): push-%:
	@$(MAKE) --no-print-directory ARCH=$* push

#-----------------------------------------------------------------------------
# Target: init
#-----------------------------------------------------------------------------
.PHONY: init
init: $(BUILD_DIRS)

# Initialize directories for build container to avoid root permissions
$(BUILD_DIRS):
	@mkdir -p $@

.PHONY: mod-vendor
# Copies dependencies into a vendor directory
mod-vendor: mod-tidy
	@go mod vendor

.PHONY: mod-tidy
# Cleans up unused dependencies
mod-tidy:
	@go mod tidy

#-----------------------------------------------------------------------------
# Target: build
#-----------------------------------------------------------------------------
.PHONY: build
build: bin/$(ARCH)/$(BIN)

.PHONY: bin/$(ARCH)/$(BIN)
bin/$(ARCH)/$(BIN): init
	@echo "building: $@"
	@$(DOCKER_RUN)             \
	    /bin/sh -c "           \
	        ARCH=$(ARCH)       \
	        VERSION=$(VERSION) \
	        PKG=$(PKG)         \
	        ./build/build.sh   \
	    "

#-----------------------------------------------------------------------------
# Target: docker build and push
#-----------------------------------------------------------------------------
DOTFILE_IMAGE = $(subst :,_,$(subst /,_,$(IMAGE))-$(VERSION))

.PHONY: container .container-$(DOTFILE_IMAGE)
container: .container-$(DOTFILE_IMAGE) container-name
.container-$(DOTFILE_IMAGE): build Dockerfile.in
	@sed \
	    -e 's|ARG_BIN|$(BIN)|g' \
	    -e 's|ARG_ARCH|$(ARCH)|g' \
	    -e 's|ARG_FROM|$(BASE_IMAGE)|g' \
	    Dockerfile.in > .dockerfile-$(ARCH)
	@docker build -t $(IMAGE):$(VERSION) -f .dockerfile-$(ARCH) .
	@docker images -q $(IMAGE):$(VERSION) > $@

.PHONY: container-name
container-name:
	@echo "container: $(IMAGE):$(VERSION)"

.PHONY: push .push-$(DOTFILE_IMAGE)
push: .push-$(DOTFILE_IMAGE) push-name
.push-$(DOTFILE_IMAGE): .container-$(DOTFILE_IMAGE)
ifeq ($(findstring gcr.io,$(REGISTRY)),gcr.io)
	@gcloud auth configure-docker
	@docker push $(IMAGE):$(VERSION)
else
	@docker push $(IMAGE):$(VERSION)
endif
	@docker images -q $(IMAGE):$(VERSION) > $@

.PHONY: push-name
push-name:
	@echo "pushed: $(IMAGE):$(VERSION)"

.PHONY: version
version:
	@echo $(VERSION)

#-----------------------------------------------------------------------------
# Target: test
#-----------------------------------------------------------------------------
.PHONY: test
test: init
	@$(DOCKER_RUN) /bin/sh -c "./build/test.sh $(SRC_DIRS)"

#-----------------------------------------------------------------------------
# Target: tools
#-----------------------------------------------------------------------------
.PHONY: shell
# Example: make shell CMD="-c 'date > datefile'"
shell: init
	@echo "launching a shell in the containerized build environment"
	@$(DOCKER_RUN) /bin/sh $(CMD)

.PHONY: lint-go
lint-go:
	@docker run												\
		--rm 												\
		-u $$(id -u):$$(id -g)                              \
		-v "$(CURDIR)/.go/.cache:/.cache"                   \
		-v "$$(pwd):/app"									\
		-w /app												\
		golangci/golangci-lint:$(GOLANGCI_LINT_VERSION)		\
		golangci-lint run -v -c "/app/.golangci.yml"

.PHONY: format-go
format-go:
	@docker run												\
		--rm 												\
		-u $$(id -u):$$(id -g)                              \
		-v "$(CURDIR)/.go/.cache:/.cache"                   \
		-v "$$(pwd):/app"									\
		-w /app												\
		golangci/golangci-lint:$(GOLANGCI_LINT_VERSION)		\
		golangci-lint run --fix -v -c "/app/.golangci-format.yml"

#-----------------------------------------------------------------------------
# Target: clean
#-----------------------------------------------------------------------------
.PHONY: clean clean-container clean-build

clean: clean-container clean-build

clean-container:
	rm -rf .container-* .dockerfile-* .push-*

clean-build:
	rm -rf .go bin
