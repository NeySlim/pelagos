# SPDX-License-Identifier: Apache-2.0
# Run these on lab-dev (see AGENTS.md). The workstation only edits and runs git.

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

.PHONY: dev venv npm lint fmt test test-daemon test-lab build-frontend run run-backend run-frontend clean
.PHONY: deb rpm docker docker-allinone packages version

dev: venv npm

venv:
	cd $(BACKEND) && $(UV) venv --python $(PYTHON) .venv --allow-existing
	cd $(BACKEND) && $(UV) pip install --python .venv/bin/python -e '.[dev]'

npm:
	cd $(FRONTEND) && npm install --no-fund --no-audit

lint:
	cd $(BACKEND) && .venv/bin/ruff check pelagos tests
	cd $(BACKEND) && .venv/bin/ruff format --check pelagos tests
	cd $(FRONTEND) && npm run lint

fmt:
	cd $(BACKEND) && .venv/bin/ruff check --fix pelagos tests
	cd $(BACKEND) && .venv/bin/ruff format pelagos tests
	cd $(FRONTEND) && npm run lint:fix

test:
	cd $(BACKEND) && .venv/bin/pytest -m unit
	cd $(FRONTEND) && npx vitest run

test-daemon:
	cd $(BACKEND) && .venv/bin/pytest -m daemon

test-lab:
	cd $(BACKEND) && PELAGOS_LAB=1 .venv/bin/pytest -m lab

build-frontend:
	cd $(FRONTEND) && npm run build

run-backend:
	cd $(BACKEND) && test -f .pelagos-dev/etc/node.toml || PELAGOS_ADMIN_PASSWORD=admin-dev-password .venv/bin/pelagos --home .pelagos-dev init --name dev
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
