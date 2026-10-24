# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# Pelagos node image: the web process and the collector, without BIND or Kea.
# Build from the repository root: docker build -f docker/Dockerfile -t pelagos .
# frontend/dist is picked up when it exists; otherwise the API-only notice page is served.

FROM debian:trixie-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
ARG PELAGOS_WHEELS=
RUN PELAGOS_PYTHON=python3 packaging/build-tree.sh /out /src

FROM debian:trixie-slim
ARG PELAGOS_UID=8443
ARG PELAGOS_GID=8443
LABEL org.opencontainers.image.title="Pelagos" \
      org.opencontainers.image.description="DNS and DHCP management for BIND 9 and Kea (node image)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/NeySlim/pelagos"
# bind9-utils: rndc, named-checkconf and tsig-keygen used against the BIND container.
# util-linux: setpriv drops privileges in the entrypoint. curl serves the healthcheck.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 openssl ca-certificates bind9-utils curl util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 53 bind \
 && groupadd -g "$PELAGOS_GID" pelagos \
 && useradd -u "$PELAGOS_UID" -g pelagos -G bind -d /var/lib/pelagos -s /usr/sbin/nologin -r pelagos \
 && install -d -o pelagos -g pelagos -m 0750 /etc/pelagos /var/lib/pelagos /run/pelagos
COPY --from=builder /out/opt/pelagos /opt/pelagos
COPY docker/bind/named.conf /usr/share/pelagos/seed/bind/named.conf
COPY docker/kea/ /usr/share/pelagos/seed/kea/
COPY docker/entrypoint.sh /usr/local/bin/pelagos-entrypoint
COPY LICENSE NOTICE /usr/share/doc/pelagos/
RUN chmod 0755 /usr/local/bin/pelagos-entrypoint && ln -s /opt/pelagos/bin/pelagos /usr/bin/pelagos
ENV PELAGOS_KEA_GID=8443 PELAGOS_BIND_GID=53 PYTHONUNBUFFERED=1
VOLUME ["/etc/pelagos", "/var/lib/pelagos"]
EXPOSE 8443 8444
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsk https://127.0.0.1:8443/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/pelagos-entrypoint"]
CMD ["serve"]
