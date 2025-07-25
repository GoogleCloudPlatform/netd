# Copyright 2016 The Kubernetes Authors.
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

DBG_MAKEFILE ?=
ifeq ($(DBG_MAKEFILE),1)
    $(warning ***** starting Makefile for goal(s) "$(MAKECMDGOALS)")
    $(warning ***** $(shell date))
else
    # If we're not debugging the Makefile, don't echo recipes.
    MAKEFLAGS += -s
endif

# The binaries to build (just the basenames)
BINS ?= netd-init

# The platforms we support.  In theory this can be used for Windows platforms,
# too, but they require specific base images, which we do not have.
ALL_PLATFORMS ?= linux/amd64 linux/arm linux/arm64 linux/ppc64le linux/s390x

# The "FROM" part of the Dockerfile.  This should be a manifest-list which
# supports all of the platforms listed in ALL_PLATFORMS.
BASE_IMAGE ?= registry.k8s.io/build-image/distroless-iptables:v0.7.6

# Where to push the docker images.
REGISTRY ?= gcr.io/gke-release-staging

# This version-strategy uses git tags to set the version string
VERSION ?= $(shell git describe --tags --always --dirty)
#
# This version-strategy uses a manual value to set the version string
#VERSION ?= 1.2.3

# Set this to 1 to build a debugger-friendly binaries.
DBG ?=

# Third party binary dependencies.
CURL_VERSION ?= 8.4.0
JQ_VERSION ?= 1.6
TOYBOX_VERSION ?= 0.8.9
SPDX_LICENSE_VERSION ?= 3.18

THIRD_PARTY_SOURCE_FILES = third_party/curl status.d/curl third_party/jq status.d/jq third_party/toybox status.d/toybox third_party/license-list-data

###
### These variables should not need tweaking.
###

UC = $(shell echo '$*' | tr '[:lower:]' '[:upper:]')

# We don't need make's built-in rules.
MAKEFLAGS += --no-builtin-rules
# Be pedantic about undefined variables.
MAKEFLAGS += --warn-undefined-variables
.SUFFIXES:

# Used internally.  Users should pass GOOS and/or GOARCH.
OS := $(if $(GOOS),$(GOOS),$(shell GOTOOLCHAIN=local go env GOOS))
ARCH := $(if $(GOARCH),$(GOARCH),$(shell GOTOOLCHAIN=local go env GOARCH))

TAG := $(VERSION)__$(OS)_$(ARCH)

GO_VERSION := 1.24
BUILD_IMAGE := golang:$(GO_VERSION)-alpine

BIN_EXTENSION :=
ifeq ($(OS), windows)
  BIN_EXTENSION := .exe
endif

# It's necessary to set this because some environments don't link sh -> bash.
SHELL := /usr/bin/env bash -o errexit -o pipefail -o nounset

# This is used in docker buildx commands
BUILDX_NAME := $(shell basename $$(pwd))

# Satisfy --warn-undefined-variables.
GOFLAGS ?=
HTTP_PROXY ?=
HTTPS_PROXY ?=

# Because we store the module cache locally.
GOFLAGS := $(GOFLAGS) -modcacherw

# If you want to build all binaries, see the 'all-build' rule.
# If you want to build all containers, see the 'all-container' rule.
# If you want to build AND push all containers, see the 'all-push' rule.
all: # @HELP builds binaries for one platform ($OS/$ARCH)
all: build

# For the following OS/ARCH expansions, we transform OS/ARCH into OS_ARCH
# because make pattern rules don't match with embedded '/' characters.

build-%:
	$(MAKE) build                         \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

container-%:
	$(MAKE) container                     \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

push-%:
	$(MAKE) push                          \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

all-build: # @HELP builds binaries for all platforms
all-build: $(addprefix build-, $(subst /,_, $(ALL_PLATFORMS)))

all-container: # @HELP builds containers for all platforms
all-container: $(addprefix container-, $(subst /,_, $(ALL_PLATFORMS)))

all-push: # @HELP pushes containers for all platforms to the defined registry
all-push: $(addprefix push-, $(subst /,_, $(ALL_PLATFORMS)))

# The following structure defeats Go's (intentional) behavior to always touch
# result files, even if they have not changed.  This will still run `go` but
# will not trigger further work if nothing has actually changed.
OUTBINS = $(foreach bin,$(BINS),bin/$(OS)_$(ARCH)/$(bin)$(BIN_EXTENSION))

build: $(OUTBINS)
	echo

# Directories that we need created to build/test.
BUILD_DIRS := bin/$(OS)_$(ARCH)                   \
              bin/tools                           \
              .go/bin/$(OS)_$(ARCH)               \
              .go/bin/$(OS)_$(ARCH)/$(OS)_$(ARCH) \
              .go/cache

# Each outbin target is just a facade for the respective stampfile target.
# This `eval` establishes the dependencies for each.
$(foreach outbin,$(OUTBINS),$(eval  \
    $(outbin): .go/$(outbin).stamp  \
))
# This is the target definition for all outbins.
$(OUTBINS):
	true

# Each stampfile target can reference an $(OUTBIN) variable.
$(foreach outbin,$(OUTBINS),$(eval $(strip   \
    .go/$(outbin).stamp: OUTBIN = $(outbin)  \
)))
# This is the target definition for all stampfiles.
# This will build the binary under ./.go and update the real binary iff needed.
STAMPS = $(foreach outbin,$(OUTBINS),.go/$(outbin).stamp)
.PHONY: $(STAMPS)
$(STAMPS): go-build
	echo -ne "binary: $(OUTBIN)  "
	if ! cmp -s .go/$(OUTBIN) $(OUTBIN); then  \
	    mv .go/$(OUTBIN) $(OUTBIN);            \
	    date >$@;                              \
	    echo;                                  \
	else                                       \
	    echo "(cached)";                       \
	fi

# This runs the actual `go build` which updates all binaries.
go-build: | $(BUILD_DIRS)
	echo "# building for $(OS)/$(ARCH)"
	docker run                                                  \
	    -i                                                      \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env GOCACHE="/.cache/gocache"                         \
	    --env GOMODCACHE="/.cache/gomodcache"                   \
	    --env ARCH="$(ARCH)"                                    \
	    --env OS="$(OS)"                                        \
	    --env VERSION="$(VERSION)"                              \
	    --env DEBUG="$(DBG)"                                    \
	    --env GOFLAGS="$(GOFLAGS)"                              \
	    --env HTTP_PROXY="$(HTTP_PROXY)"                        \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"                      \
	    $(BUILD_IMAGE)                                          \
	    ./build/build.sh ./...

# Example: make shell CMD="-c 'date > datefile'"
shell: # @HELP launches a shell in the containerized build environment
shell: | $(BUILD_DIRS)
	echo "# launching a shell in the containerized build environment"
	docker run                                                  \
	    -ti                                                     \
	    --rm                                                    \
	    -u $$(id -u):$$(id -g)                                  \
	    -v $$(pwd):/src                                         \
	    -w /src                                                 \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin                \
	    -v $$(pwd)/.go/bin/$(OS)_$(ARCH):/go/bin/$(OS)_$(ARCH)  \
	    -v $$(pwd)/.go/cache:/.cache                            \
	    --env GOCACHE="/.cache/gocache"                         \
	    --env GOMODCACHE="/.cache/gomodcache"                   \
	    --env ARCH="$(ARCH)"                                    \
	    --env OS="$(OS)"                                        \
	    --env VERSION="$(VERSION)"                              \
	    --env DEBUG="$(DBG)"                                    \
	    --env GOFLAGS="$(GOFLAGS)"                              \
	    --env HTTP_PROXY="$(HTTP_PROXY)"                        \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"                      \
	    $(BUILD_IMAGE)                                          \
	    /bin/sh $(CMD)

LICENSES = .licenses

$(LICENSES): ../LICENSE third_party/curl third_party/jq third_party/toybox | $(BUILD_DIRS)
	rm -rf $(LICENSES)
	mkdir -p $(LICENSES)
	cp ../LICENSE $(LICENSES)/netd-LICENSE
	cp third_party/curl/COPYING $(LICENSES)/curl-COPYING
	cp third_party/jq/COPYING $(LICENSES)/jq-COPYING
	cp third_party/toybox/LICENSE $(LICENSES)/toybox-LICENSE
	chmod -R a+rx $(LICENSES)

GIT_BASE ?= https://github.com

third_party/curl:
	git clone $(GIT_BASE)/curl/curl $@
	pushd $@; git checkout curl-$(subst .,_,$(CURL_VERSION)); autoreconf -fi; popd

third_party/jq:
	git clone $(GIT_BASE)/stedolan/jq $@
	pushd $@; git checkout jq-$(JQ_VERSION); autoreconf -fi; popd

third_party/toybox:
	git clone $(GIT_BASE)/landley/toybox $@
	pushd $@; git checkout $(TOYBOX_VERSION); popd

third_party/license-list-data:
	git clone $(GIT_BASE)/spdx/license-list-data $@
	pushd $@; git checkout v$(SPDX_LICENSE_VERSION); popd

status.d/%:
	mkdir -p status.d
	echo Package: $* > $@
	echo Version: $($(UC)_VERSION) >> $@

CONTAINER_DOTFILES = $(foreach bin,$(BINS),.container-$(subst /,_,$(REGISTRY)/$(bin))-$(TAG))

# We print the container names here, rather than in CONTAINER_DOTFILES so
# they are always at the end of the output.
container containers: # @HELP builds containers for one platform ($OS/$ARCH)
container containers: $(CONTAINER_DOTFILES)
	for bin in $(BINS); do                           \
	    echo "container: $(REGISTRY)/$$bin:$(TAG)";  \
	done
	echo

# Each container-dotfile target can reference a $(BIN) variable.
# This is done in 2 steps to enable target-specific variables.
$(foreach bin,$(BINS),$(eval $(strip                                 \
    .container-$(subst /,_,$(REGISTRY)/$(bin))-$(TAG): BIN = $(bin)  \
)))
$(foreach bin,$(BINS),$(eval                                         \
    .container-$(subst /,_,$(REGISTRY)/$(bin))-$(TAG): bin/$(OS)_$(ARCH)/$(bin)$(BIN_EXTENSION) $(LICENSES) Dockerfile.in  \
))
# This is the target definition for all container-dotfiles.
# These are used to track build state in hidden files.
$(CONTAINER_DOTFILES): .buildx-initialized $(THIRD_PARTY_SOURCE_FILES)
	echo
	sed                                            \
	    -e 's|{ARG_BIN}|$(BIN)$(BIN_EXTENSION)|g'  \
	    -e 's|{ARG_ARCH}|$(ARCH)|g'                \
	    -e 's|{ARG_OS}|$(OS)|g'                    \
	    -e 's|{ARG_FROM}|$(BASE_IMAGE)|g'          \
	    Dockerfile.in > .dockerfile-$(BIN)-$(OS)_$(ARCH)
	HASH_LICENSES=$$(find $(LICENSES) -type f                       \
		    | xargs md5sum | md5sum | cut -f1 -d' ');           \
	HASH_BINARY=$$(md5sum bin/$(OS)_$(ARCH)/$(BIN)$(BIN_EXTENSION)  \
		    | cut -f1 -d' ');                                   \
	FORCE=0;                                                        \
	docker buildx build                                             \
	    --builder "$(BUILDX_NAME)"                                  \
	    --build-arg FORCE_REBUILD="$$FORCE"                         \
	    --build-arg HASH_LICENSES="$$HASH_LICENSES"                 \
	    --build-arg HASH_BINARY="$$HASH_BINARY"                     \
	    --progress=plain                                            \
	    --load                                                      \
	    --platform "$(OS)/$(ARCH)"                                  \
	    --build-arg HTTP_PROXY="$(HTTP_PROXY)"                      \
	    --build-arg HTTPS_PROXY="$(HTTPS_PROXY)"                    \
	    -t $(REGISTRY)/$(BIN):$(TAG)                                \
	    -f .dockerfile-$(BIN)-$(OS)_$(ARCH)                         \
	    .
	docker images -q $(REGISTRY)/$(BIN):$(TAG) > $@
	echo

push: # @HELP pushes the container for one platform ($OS/$ARCH) to the defined registry
push: container
	for bin in $(BINS); do                     \
	    docker push $(REGISTRY)/$$bin:$(TAG);  \
	done
	echo

# This depends on github.com/estesp/manifest-tool.
manifest-list: # @HELP builds a manifest list of containers for all platforms
manifest-list: all-push
	# Don't assume that `go` is available locally.
	docker run                                 \
	    -i                                     \
	    --rm                                   \
	    -u $$(id -u):$$(id -g)                 \
	    -v $$(pwd)/tools:/src                  \
	    -w /src                                \
	    -v $$(pwd)/bin/tools:/go/bin           \
	    -v $$(pwd)/.go/cache:/.cache           \
	    --env GOCACHE="/.cache/gocache"        \
	    --env GOMODCACHE="/.cache/gomodcache"  \
	    --env CGO_ENABLED=0                    \
	    --env HTTP_PROXY="$(HTTP_PROXY)"       \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"     \
	    $(BUILD_IMAGE)                         \
	    go install github.com/estesp/manifest-tool/v2/cmd/manifest-tool
	for bin in $(BINS); do                                    \
	    platforms=$$(echo $(ALL_PLATFORMS) | sed 's/ /,/g');  \
	    bin/tools/manifest-tool                               \
	        --username=oauth2accesstoken                      \
	        --password=$$(gcloud auth print-access-token)     \
	        push from-args                                    \
	        --platforms "$$platforms"                         \
	        --template $(REGISTRY)/$$bin:$(VERSION)__OS_ARCH  \
	        --target $(REGISTRY)/$$bin:$(VERSION);            \
	done

version: # @HELP outputs the version string
version:
	echo $(VERSION)

test-inotify:
	echo "Building and testing inotify"
	docker run                              \
	    -i                                  \
	    --rm                                \
	    -v $$(pwd)/inotify:/src             \
	    --env HTTP_PROXY="$(HTTP_PROXY)"    \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"  \
	    alpine:3.16                         \
	    sh -c 'cp -a /src /inotify && cd /inotify && ./build.sh && ./test.sh'

test-shell: container
	echo "Running shell-test.sh"
	docker run                              \
	    -i                                  \
	    --rm                                \
	    -v $$(pwd)/shell-test.sh:/test.sh   \
	    --env HTTP_PROXY="$(HTTP_PROXY)"    \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"  \
	    $(REGISTRY)/$(BINS):$(TAG)          \
	    /test.sh

test-install-cni: container
	echo "Testing install-cni.sh"
	docker run                              \
	    -i                                  \
	    --rm                                \
	    -v $$(pwd)/test.out:/host/etc/cni/net.d \
	    -v $$(pwd)/testdata/token:/var/run/secrets/kubernetes.io/serviceaccount/token \
	    -v $$(pwd):/src                     \
	    --workdir /src                      \
	    --env HTTP_PROXY="$(HTTP_PROXY)"    \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"  \
	    $(REGISTRY)/$(BINS):$(TAG)          \
	    /src/test-install-cni.sh

test: # @HELP runs tests
test: test-inotify test-shell test-install-cni

lint: # @HELP runs lint
lint:
	echo "Linting inotify"
	docker run                              \
	    -i                                  \
	    --rm                                \
	    -v $$(pwd)/inotify:/src             \
	    -w /src                             \
	    --env HTTP_PROXY="$(HTTP_PROXY)"    \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"  \
	    python:3-alpine                     \
	    sh -c 'pip install cpplint==1.6.1 && cpplint --recursive .'
	echo "Linting install-cni.sh"
	docker run                              \
	    -i                                  \
	    --rm                                \
	    -u $$(id -u):$$(id -g)              \
	    -v $$(pwd):/src                     \
	    -w /src                             \
	    --env HTTP_PROXY="$(HTTP_PROXY)"    \
	    --env HTTPS_PROXY="$(HTTPS_PROXY)"  \
	    koalaman/shellcheck                 \
	    -s bash                             \
	    install-cni.sh                      \
	    test-install-cni.sh testcase/testcase-*.sh

$(BUILD_DIRS):
	mkdir -p $@

clean: # @HELP removes built binaries and temporary files
clean: container-clean bin-clean third-party-source-clean

container-clean:
	rm -rf .container-* .dockerfile-* .push-* .buildx-initialized $(LICENSES)

bin-clean:
	test -d .go && chmod -R u+w .go || true
	rm -rf .go bin

third-party-source-clean:
	rm -rf $(THIRD_PARTY_SOURCE_FILES)

help: # @HELP prints this message
help:
	echo "VARIABLES:"
	echo "  BINS = $(BINS)"
	echo "  OS = $(OS)"
	echo "  ARCH = $(ARCH)"
	echo "  DBG = $(DBG)"
	echo "  GOFLAGS = $(GOFLAGS)"
	echo "  REGISTRY = $(REGISTRY)"
	echo
	echo "TARGETS:"
	grep -E '^.*: *# *@HELP' $(MAKEFILE_LIST)     \
	    | awk '                                   \
	        BEGIN {FS = ": *# *@HELP"};           \
	        { printf "  %-30s %s\n", $$1, $$2 };  \
	    '

# Help set up multi-arch build tools.  This assumes you have the tools
# installed.  If you already have a buildx builder available, you don't need
# this.  See https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408
# for great context.
.buildx-initialized:
	docker buildx create --name "$(BUILDX_NAME)" --node "$(BUILDX_NAME)-0" >/dev/null
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes >/dev/null
	date > $@
