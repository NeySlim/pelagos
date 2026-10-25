# SPDX-License-Identifier: Apache-2.0
# Development, test and packaging targets. Toolchain and test tiers: see AGENTS.md.

UV        ?= $(shell command -v uv 2>/dev/null || echo $(HOME)/.local/bin/uv)
PYTHON    ?= 3.12
BACKEND   := backend
FRONTEND  := frontend
VENV      := $(BACKEND)/.venv
PY        := $(VENV)/bin/python
PYTEST    := $(VENV)/bin/pytest
RUFF      := $(VENV)/bin/ruff
export PATH := /usr/sbin:/usr/local/sbin:$(PATH)

VERSION   := $(shell packaging/version.sh python)
IMAGE     ?= pelagos
DOCKER    ?= docker

.PHONY: dev venv npm lint lint-backend lint-frontend fmt test test-unit test-vitest test-daemon test-lab test-e2e
.PHONY: screenshots build-frontend run run-backend run-frontend clean messages-keys
.PHONY: deb rpm docker docker-allinone packages version lock wheels test-packaging

dev: venv npm

venv:
	cd $(BACKEND) && $(UV) venv --python $(PYTHON) .venv --allow-existing
	cd $(BACKEND) && $(UV) pip install --python .venv/bin/python -e '.[dev]'

npm:
	cd $(FRONTEND) && npm install --no-fund --no-audit

lint: lint-backend lint-frontend

lint-backend:
	cd $(BACKEND) && .venv/bin/ruff check pelagos tests
	cd $(BACKEND) && .venv/bin/ruff format --check pelagos tests

lint-frontend:
	cd $(FRONTEND) && npm run lint

fmt:
	cd $(BACKEND) && .venv/bin/ruff check --fix pelagos tests
	cd $(BACKEND) && .venv/bin/ruff format pelagos tests
	cd $(FRONTEND) && npm run lint:fix

test: test-unit test-vitest

test-unit:
	cd $(BACKEND) && .venv/bin/pytest -m unit $(PYTEST_ARGS)

test-vitest:
	cd $(FRONTEND) && npx vitest run

# Regenerate the key list the frontend checks its catalogs against (after editing CATALOG).
messages-keys:
	cd $(BACKEND) && .venv/bin/python -m pelagos.domain.messages > ../$(FRONTEND)/src/i18n/backendMessageKeys.json

test-daemon:
	cd $(BACKEND) && .venv/bin/pytest -m daemon $(PYTEST_ARGS)

# Playwright against the mock server (npx playwright install chromium once).
test-e2e:
	cd $(FRONTEND) && npx playwright test

# README and user documentation screenshots from the mock server, Instrument theme, dark and light.
screenshots:
	cd $(FRONTEND) && node e2e/screenshots.mjs ../docs/images

test-lab:
	cd $(BACKEND) && PELAGOS_LAB=1 .venv/bin/pytest -m lab --timeout 3600 -x $(LAB_ARGS)

build-frontend:
	cd $(FRONTEND) && npm run build

run-backend:
	cd $(BACKEND) && test -f .pelagos-dev/etc/node.toml || PELAGOS_ADMIN_PASSWORD=Admin-Dev-Password-1 .venv/bin/pelagos --home .pelagos-dev init --name dev
	cd $(BACKEND) && .venv/bin/pelagos --home .pelagos-dev serve --bind 127.0.0.1:8480

run-frontend:
	cd $(FRONTEND) && npm run dev -- --host 127.0.0.1

run:
	$(MAKE) -j2 run-backend run-frontend

clean:
	rm -rf $(VENV) $(BACKEND)/.pytest_cache $(BACKEND)/.ruff_cache $(FRONTEND)/dist build
	find $(BACKEND) -name __pycache__ -type d -prune -exec rm -rf {} +

# Packaging (WP-PACKAGING). Each target takes frontend/dist when it exists and ships the
# API-only notice page otherwise: run build-frontend first for a package with the UI.
version:
	@echo "python $(VERSION)  deb/rpm $(shell packaging/version.sh deb)  docker $(shell packaging/version.sh docker)"

deb:
	packaging/deb/build.sh build/deb

rpm:
	packaging/rpm/build.sh build/rpm

docker:
	$(DOCKER) build -f docker/Dockerfile -t $(IMAGE):$(shell packaging/version.sh docker) -t $(IMAGE):latest .

docker-allinone:
	$(DOCKER) build -f docker/allinone/Dockerfile --build-arg KEA_SOURCE=$(or $(KEA_SOURCE),isc) \
		-t $(IMAGE)-allinone:$(shell packaging/version.sh docker) -t $(IMAGE)-allinone:latest .

packages: deb rpm docker docker-allinone

# Pinned runtime dependencies (with hashes) installed by packaging/build-tree.sh.
lock:
	printf '# SPDX-License-Identifier: Apache-2.0\n# Pinned runtime dependencies of the packages and images. Regenerate with: make lock\n' \
		> packaging/requirements.lock
	$(UV) pip compile $(BACKEND)/pyproject.toml --universal --python-version 3.12 --generate-hashes \
		--no-header --annotation-style line --quiet >> packaging/requirements.lock

# Wheels for an offline build with the same interpreter and platform as the package build:
# make wheels && PELAGOS_WHEELS=$(CURDIR)/build/wheels make deb
wheels:
	mkdir -p build/wheels
	$(or $(PELAGOS_PYTHON),python3) -m pip download --quiet --dest build/wheels --require-hashes -r packaging/requirements.lock
	$(or $(PELAGOS_PYTHON),python3) -m pip download --quiet --dest build/wheels hatchling

# Shell helpers of the packages (needs root or passwordless sudo).
test-packaging:
	packaging/tests/scripts-test.sh
