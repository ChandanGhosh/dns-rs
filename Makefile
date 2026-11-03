# dns-rs developer tasks.
#
# Run `make` or `make help` for the target list. Variables can be overridden
# on the command line, for example:
#
#   make checkconf CONFIG=examples/full.toml
#   make bench THREADS="1 2" BENCH_DURATION=30
#   make bench-compare BASE_REF=e4176ff THREADS="1 2 4"
#   make image IMAGE=dns-rs:local
#   make image-publish TAG=dev CONFIRM=1

SHELL := /bin/bash
.DEFAULT_GOAL := help

CARGO ?= cargo
DOCKER ?= docker
TRIVY ?= trivy

CONFIG ?= examples/minimal.toml
THREADS ?= 1 2 4
BASE_REF ?= origin/main

IMAGE ?= dns-rs:dev
CONTAINER ?= dns-rs-smoke
PORT ?= 15353
KEEP ?= 0
PLATFORM ?=
DOCKER_RUN_ARGS ?=

VERSION ?= $(shell sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
VCS_REF ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
SOURCE_URL ?= $(shell git config --get remote.origin.url 2>/dev/null || true)
PLATFORMS ?= linux/amd64,linux/arm64
REGISTRY_IMAGE ?= chandanghosh/dns-rs
TAG ?=
CONFIRM ?=

IMAGE_SIZE_LIMIT ?= 10485760
TRIVY_SEVERITY ?= CRITICAL,HIGH
FUZZ_RUNS ?= 20000
FUZZ_SECONDS ?= 60
FUZZ_TARGET ?= x86_64-unknown-linux-gnu

# Build arguments shared by local and multi-arch builds. `VERSION` is the
# workspace semver, which the image also reports through `dns-rs --version`.
DOCKER_BUILD_ARGS = \
	--build-arg VERSION="$(VERSION)" \
	--build-arg VCS_REF="$(VCS_REF)" \
	--build-arg BUILD_DATE="$(BUILD_DATE)" \
	--build-arg SOURCE_URL="$(SOURCE_URL)"

.PHONY: help doctor tools version \
	build release dist run run-release checkconf checkconf-examples healthcheck install \
	clean clean-image \
	fmt fmt-check clippy test test-doc test-all deny audit fuzz check ci \
	coverage coverage-html \
	bench bench-container bench-ci bench-compare \
	image image-multiarch image-smoke image-size image-scan image-publish \
	docker-run container-check ci-container ci-all \
	compose-up compose-up-local compose-down compose-clean compose-logs compose-ps \
	doc doc-open

# Cargo and Docker contend for locks and CPU; keep aggregate targets ordered.
.NOTPARALLEL: check ci test-all container-check ci-container ci-all

##@ General

help: ## Show this help
	@printf 'Usage: make <target> [VARIABLE=value]\n'
	@awk 'BEGIN { FS = ":.*## " } \
		/^##@/ { printf "\n%s\n", substr($$0, 5) } \
		/^[a-zA-Z0-9_.-]+:.*## / { printf "  %-24s %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)
	@printf '\nVariables (override on the command line or in the environment):\n'
	@printf '  %-24s %s\n' 'CARGO/DOCKER/TRIVY' 'tool overrides'
	@printf '  %-24s %s\n' 'CONFIG' 'configuration file (default: $(CONFIG))'
	@printf '  %-24s %s\n' 'THREADS' 'benchmark worker counts (default: $(THREADS))'
	@printf '  %-24s %s\n' 'BENCH_*' 'passed to scripts/bench-loopback.sh'
	@printf '  %-24s %s\n' 'BASE_REF' 'bench-compare baseline ref (default: $(BASE_REF))'
	@printf '  %-24s %s\n' 'AB_*' 'bench-compare pair/load controls (AB_REPEATS, AB_LOAD_LIMIT)'
	@printf '  %-24s %s\n' 'IMAGE' 'local image tag (default: $(IMAGE))'
	@printf '  %-24s %s\n' 'CONTAINER' 'smoke-test container name (default: $(CONTAINER))'
	@printf '  %-24s %s\n' 'PORT' 'smoke-test and docker-run host port (default: $(PORT))'
	@printf '  %-24s %s\n' 'KEEP' 'keep the smoke container running (default: $(KEEP))'
	@printf '  %-24s %s\n' 'PLATFORM' 'smoke-test/docker-run platform (default: host)'
	@printf '  %-24s %s\n' 'DOCKER_RUN_ARGS' 'extra flags for docker-run'
	@printf '  %-24s %s\n' 'PLATFORMS' 'multi-arch platforms (default: $(PLATFORMS))'
	@printf '  %-24s %s\n' 'REGISTRY_IMAGE' 'publish repository (default: $(REGISTRY_IMAGE))'
	@printf '  %-24s %s\n' 'VERSION' 'workspace semver baked into the image (default: $(VERSION))'
	@printf '  %-24s %s\n' 'TAG' 'publish tag; required by image-publish'
	@printf '  %-24s %s\n' 'CONFIRM' 'set to 1 to allow image-publish'
	@printf '  %-24s %s\n' 'IMAGE_SIZE_LIMIT' 'size gate in bytes (default: $(IMAGE_SIZE_LIMIT))'
	@printf '  %-24s %s\n' 'TRIVY_SEVERITY' 'Trivy severities (default: $(TRIVY_SEVERITY))'
	@printf '  %-24s %s\n' 'FUZZ_RUNS' 'fuzz iterations (default: $(FUZZ_RUNS))'
	@printf '  %-24s %s\n' 'FUZZ_SECONDS' 'fuzz time limit in seconds (default: $(FUZZ_SECONDS))'
	@printf '  %-24s %s\n' 'FUZZ_TARGET' 'fuzz build target (default: $(FUZZ_TARGET))'

doctor: ## Show tool versions and which optional tools are available
	@printf 'Required:\n'
	@printf '  %-16s %s\n' 'cargo' "$$(cargo --version 2>/dev/null || echo MISSING)"
	@printf '  %-16s %s\n' 'rustc' "$$(rustc --version 2>/dev/null || echo MISSING)"
	@printf '  %-16s %s\n' 'make' "$$(make --version 2>/dev/null | head -n 1 || echo MISSING)"
	@printf '\nOptional:\n'
	@for tool in cargo-nextest cargo-deny cargo-audit cargo-fuzz \
		cargo-llvm-cov docker trivy dig; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			case "$$tool" in \
				dig) version="$$(dig -v 2>&1 | head -n 1)" ;; \
				*) version="$$("$$tool" --version 2>/dev/null | head -n 1)" ;; \
			esac; \
			printf '  %-16s %s\n' "$$tool" "$${version:-installed}"; \
		else \
			printf '  %-16s %s\n' "$$tool" 'missing'; \
		fi; \
	done

tools: ## Install the optional Rust tools used by check/ci/coverage
	@for tool in cargo-nextest cargo-deny cargo-audit cargo-fuzz \
		cargo-llvm-cov; do \
		if command -v "$$tool" >/dev/null 2>&1; then \
			echo "$$tool: already installed"; \
		else \
			echo "installing $$tool"; \
			$(CARGO) install --locked "$$tool" || exit 1; \
		fi; \
	done

##@ Build

version: ## Print the workspace version used for image labels and releases
	@echo "$(VERSION)"

build: fmt ## Build all workspace crates (debug)
	$(CARGO) build --workspace --all-features

release: ## Build the daemon with the release profile
	$(CARGO) build --release --package dns-daemon --bin dns-rs

dist: ## Build the daemon with the container `dist` profile
	$(CARGO) build --profile dist --package dns-daemon --bin dns-rs

run: ## Run the resolver with CONFIG
	$(CARGO) run --package dns-daemon -- run -c "$(CONFIG)"

run-release: ## Run the release resolver with CONFIG
	$(CARGO) run --release --package dns-daemon -- run -c "$(CONFIG)"

checkconf: ## Validate CONFIG
	$(CARGO) run --quiet --package dns-daemon -- checkconf -c "$(CONFIG)"

checkconf-examples: ## Validate every example configuration
	@set -e; for config in examples/*.toml examples/*.conf; do \
		[ -e "$$config" ] || continue; \
		echo "checking $$config"; \
		$(CARGO) run --quiet --package dns-daemon -- checkconf -c "$$config"; \
	done

healthcheck: ## Probe the resolver described by CONFIG
	$(CARGO) run --quiet --package dns-daemon -- -c "$(CONFIG)" healthcheck

install: ## Install the dns-rs binary into ~/.cargo/bin
	$(CARGO) install --locked --path crates/dns-daemon --bin dns-rs

clean: ## Remove Cargo build artifacts
	$(CARGO) clean

clean-image: ## Remove the local container image
	-$(DOCKER) image rm --force "$(IMAGE)"

##@ Quality

fmt: ## Format the workspace
	$(CARGO) fmt --all

fmt-check: ## Check formatting without changing files
	$(CARGO) fmt --all --check

clippy: ## Run Clippy with the CI lint level
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test: ## Run tests (nextest when installed, cargo test otherwise)
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		$(CARGO) nextest run --workspace --all-features; \
	else \
		$(CARGO) test --workspace --all-features \
			--lib --bins --tests --examples; \
	fi

test-doc: ## Run doctests
	$(CARGO) test --workspace --doc

test-all: test test-doc ## Run unit, integration, and doc tests

deny: ## Check dependency licenses, advisories, bans, and sources
	@command -v cargo-deny >/dev/null 2>&1 || { \
		echo "cargo-deny is not installed; run 'make tools'"; exit 1; }
	$(CARGO) deny check

audit: ## Check dependencies for known vulnerabilities
	@command -v cargo-audit >/dev/null 2>&1 || { \
		echo "cargo-audit is not installed; run 'make tools'"; exit 1; }
	$(CARGO) audit

fuzz: ## Run the decoder fuzz smoke test
	@command -v cargo-fuzz >/dev/null 2>&1 || { \
		echo "cargo-fuzz is not installed; run 'make tools'"; exit 1; }
	cd fuzz && $(CARGO) fuzz run decode_message \
		--target $(FUZZ_TARGET) -- \
		-runs=$(FUZZ_RUNS) -max_total_time=$(FUZZ_SECONDS)

check: fmt-check clippy test-all deny checkconf-examples ## Fast local gate: format, lint, tests, dependency policy, configs

ci: check audit fuzz ## Run every non-container CI gate locally

coverage: ## Show test coverage (requires cargo-llvm-cov)
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { \
		echo "cargo-llvm-cov is not installed; run 'make tools'"; exit 1; }
	$(CARGO) llvm-cov --workspace --all-features --summary-only

coverage-html: ## Write an HTML coverage report to target/llvm-cov/html
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { \
		echo "cargo-llvm-cov is not installed; run 'make tools'"; exit 1; }
	$(CARGO) llvm-cov --workspace --all-features --html
	@echo "report: target/llvm-cov/html/index.html"

##@ Benchmarks

bench: ## Run the loopback benchmark for THREADS (host binary)
	scripts/bench-loopback.sh $(THREADS)

bench-container: image ## Build IMAGE and run the loopback benchmark against it
	BENCH_SERVER_IMAGE="$(IMAGE)" scripts/bench-loopback.sh $(THREADS)

bench-ci: image ## Reproduce the CI one- and two-worker load stats
	BENCH_SERVER_IMAGE="$(IMAGE)" BENCH_NAMES=4000 BENCH_CONCURRENCY=8 \
		BENCH_WARMUP=5 BENCH_DURATION=15 scripts/bench-loopback.sh 1 2

bench-compare: ## Interleaved A/B benchmark of BASE_REF vs. the working tree
	scripts/bench-compare.sh $(BASE_REF) $(THREADS)

##@ Container

image: ## Build the local container image as IMAGE
	@test -n "$(VERSION)" || { echo "could not read the workspace version"; exit 1; }
	$(DOCKER) build $(DOCKER_BUILD_ARGS) --tag "$(IMAGE)" .

image-multiarch: ## Build amd64 and arm64 without loading or pushing
	$(DOCKER) buildx build --platform "$(PLATFORMS)" $(DOCKER_BUILD_ARGS) \
		--output type=cacheonly .

image-smoke: image ## Build IMAGE and run the hardened smoke test
	IMAGE="$(IMAGE)" CONTAINER="$(CONTAINER)" PORT="$(PORT)" KEEP="$(KEEP)" \
		PLATFORM="$(PLATFORM)" SKIP_BUILD=1 scripts/container-smoke.sh

image-size: ## Check IMAGE against the 10 MiB budget
	@size="$$($(DOCKER) image inspect --format '{{.Size}}' "$(IMAGE)" 2>/dev/null)" || { \
		echo "image $(IMAGE) not found; run 'make image'"; exit 1; }; \
	if [ "$$size" -gt "$(IMAGE_SIZE_LIMIT)" ]; then \
		echo "image $(IMAGE) is $$size bytes; limit is $(IMAGE_SIZE_LIMIT) bytes"; \
		exit 1; \
	fi; \
	awk -v size="$$size" -v limit="$(IMAGE_SIZE_LIMIT)" \
		'BEGIN { printf "image size: %.1f MiB (limit %.1f MiB)\n", size / 1048576, limit / 1048576 }'

image-scan: ## Scan IMAGE with Trivy for CRITICAL and HIGH findings
	@command -v "$(TRIVY)" >/dev/null 2>&1 || { \
		echo "trivy is not installed"; exit 1; }
	$(TRIVY) image --severity "$(TRIVY_SEVERITY)" --ignore-unfixed \
		--vuln-type os,library --exit-code 1 "$(IMAGE)"

image-publish: ## Build and push REGISTRY_IMAGE:TAG (requires TAG and CONFIRM=1)
	@test -n "$(TAG)" || { \
		echo "TAG is required, e.g. make image-publish TAG=dev CONFIRM=1"; exit 1; }
	@test "$(CONFIRM)" = "1" || { \
		echo "refusing to push; set CONFIRM=1 to confirm"; exit 1; }
	$(DOCKER) buildx build --platform "$(PLATFORMS)" $(DOCKER_BUILD_ARGS) \
		--tag "$(REGISTRY_IMAGE):$(TAG)" \
		--sbom=true --provenance=mode=max --push .

docker-run: image ## Run IMAGE in the foreground with the hardened settings
	$(DOCKER) run --rm $(DOCKER_RUN_ARGS) \
		$(if $(PLATFORM),--platform "$(PLATFORM)") \
		--read-only \
		--tmpfs /tmp:rw,noexec,nosuid,size=16m \
		--cap-drop ALL \
		--cap-add NET_BIND_SERVICE \
		--security-opt no-new-privileges=true \
		-p "127.0.0.1:$(PORT):53/udp" \
		-p "127.0.0.1:$(PORT):53/tcp" \
		"$(IMAGE)"

container-check: image-smoke image-size ## Build, smoke-test, and size-check IMAGE

ci-container: container-check bench-ci image-scan ## Run the container CI gates locally

ci-all: ci ci-container ## Run all local CI gates

##@ Compose

compose-up: ## Start the compose example with the published image
	$(DOCKER) compose up -d

compose-up-local: image ## Start the compose example with the local IMAGE
	DNS_RS_IMAGE="$(IMAGE)" $(DOCKER) compose up -d

compose-down: ## Stop and remove the compose example
	$(DOCKER) compose down

compose-clean: ## Stop compose and remove its persisted volume
	$(DOCKER) compose down -v

compose-logs: ## Follow compose logs
	$(DOCKER) compose logs -f resolver

compose-ps: ## Show compose status
	$(DOCKER) compose ps

##@ Documentation

doc: ## Build API documentation
	$(CARGO) doc --workspace --no-deps --all-features

doc-open: ## Build and open API documentation
	$(CARGO) doc --workspace --no-deps --all-features --open
