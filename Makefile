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

.PHONY: dev venv npm lint lint-backend lint-frontend lint-commits fmt test test-unit test-vitest test-daemon test-lab lab-demo test-e2e test-e2e-smoke
.PHONY: screenshots build-frontend run run-backend run-frontend clean messages-keys settings-schema notify-catalogs
.PHONY: deb rpm docker docker-allinone packages version lock wheels test-packaging release release-check

dev: venv npm

venv:
	cd $(BACKEND) && $(UV) venv --python $(PYTHON) .venv --allow-existing
	cd $(BACKEND) && $(UV) pip install --python .venv/bin/python -e '.[dev]'

npm:
	cd $(FRONTEND) && npm install --no-fund --no-audit

lint: lint-backend lint-frontend lint-commits

# Commits not yet on origin/main: the rules CI checks on push (type(scope): subject <= 72, no body).
lint-commits:
	scripts/check-commits.sh "$$(git rev-parse -q --verify origin/main || true)" HEAD

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

# Regenerate the server copy of the UI translations notifications use (after editing the catalogs).
notify-catalogs:
	cd $(BACKEND) && .venv/bin/python -m pelagos.notify.catalog ../$(FRONTEND)/src/i18n/locales

# Regenerate the settings schema the mock server serves (after editing core/settings_registry.py).
settings-schema:
	cd $(BACKEND) && .venv/bin/python -m pelagos.core.settings_registry > ../$(FRONTEND)/mock/settingsSchema.json

test-daemon:
	cd $(BACKEND) && .venv/bin/pytest -m daemon $(PYTEST_ARGS)

# Playwright against the mock server (npx playwright install chromium once).
test-e2e:
	cd $(FRONTEND) && npx playwright test

# A few specs covering the shell, DNS, DHCP and settings: what CI runs when only the frontend changed.
E2E_SMOKE ?= e2e/smoke.spec.js e2e/dns-zones.spec.js e2e/dhcp-hosts-nodes.spec.js e2e/settings.spec.js
test-e2e-smoke:
	cd $(FRONTEND) && npx playwright test $(E2E_SMOKE)

# README and user documentation screenshots from the mock server, Instrument theme, dark and light.
screenshots:
	cd $(FRONTEND) && node e2e/screenshots.mjs ../docs/images

test-lab:
	cd $(BACKEND) && PELAGOS_LAB=1 .venv/bin/pytest -m lab --timeout 3600 -x $(LAB_ARGS)

# Lab demo (scripts/lab/README.md): NODES=3 (default) leaves the pair and the Rocky node as a third node
# (HA backup, second secondary), NODES=2 the reference pair, both with Pelagos built from here.
NODES ?= 3
LAB_DEMO_2 := tests/lab/test_pair_lab.py
LAB_DEMO_3 := tests/lab/test_three_lab.py --deselect tests/lab/test_three_lab.py::TestThreeNodes::test_12_remove_the_third_node
lab-demo:
	@test -n "$(LAB_DEMO_$(NODES))" || { echo "NODES must be 2 or 3" >&2; exit 2; }
	cd $(BACKEND) && PELAGOS_LAB=1 PELAGOS_LAB_KEEP=1 .venv/bin/pytest -m lab --timeout 3600 -x $(LAB_DEMO_$(NODES))

build-frontend:
	cd $(FRONTEND) && npm run build

run-backend: $(BACKEND)/.pelagos-dev/etc/node.toml
	cd $(BACKEND) && .venv/bin/pelagos --home .pelagos-dev serve --bind 127.0.0.1:8480

# First start of the dev tree: PELAGOS_ADMIN_PASSWORD, else a generated password printed once
# and kept in backend/.pelagos-dev/admin-password (gitignored, mode 0600).
$(BACKEND)/.pelagos-dev/etc/node.toml:
	@cd $(BACKEND) && if [ -n "$$PELAGOS_ADMIN_PASSWORD" ]; then \
	  .venv/bin/pelagos --home .pelagos-dev init --name dev; \
	else \
	  PELAGOS_ADMIN_PASSWORD="$$(.venv/bin/python -c 'import re, secrets; print(next(p for p in iter(lambda: secrets.token_urlsafe(18), "") if re.search("[a-z]", p) and re.search("[A-Z]", p) and re.search("[0-9]", p)))')" \
	  && export PELAGOS_ADMIN_PASSWORD && .venv/bin/pelagos --home .pelagos-dev init --name dev \
	  && (umask 077 && printf '%s\n' "$$PELAGOS_ADMIN_PASSWORD" > .pelagos-dev/admin-password) \
	  && printf '\n  dev admin: admin / %s\n  (shown once; kept in backend/.pelagos-dev/admin-password)\n\n' "$$PELAGOS_ADMIN_PASSWORD"; \
	fi

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

# Release: make release VERSION=0.1.1 commits the version with docs/releases/0.1.1.md and
# CHANGELOG.md and tags v0.1.1 (nothing is pushed; CI builds the release, docs/dev/release.md).
# NO_TAG=1 [SINCE=<ref>] [RELEASE_DIR=<dir>]: local debs of HEAD in RELEASE_DIR/<version>/ (lab).
RELEASE_DIR ?= build/release
release:
	scripts/release.sh $(if $(NO_TAG),--no-tag) $(if $(SINCE),--since $(SINCE)) --out $(RELEASE_DIR) $(VERSION)

# Blocking checks of the release workflow: make release-check VERSION=0.1.1 [DIR=<release dir>].
release-check:
	scripts/release-check.sh --tag v$(VERSION) $(DIR)

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
