# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
# All-in-one image: BIND 9, Kea and the Pelagos node under supervisord, for hosts without
# the ISC images. Build from the repository root:
#   docker build -f docker/allinone/Dockerfile --build-arg KEA_SOURCE=isc -t pelagos-allinone .
# KEA_SOURCE=isc installs Kea 3.2 from the ISC Cloudsmith repository (default);
# KEA_SOURCE=distro installs Debian's Kea 2.6 (lease_cmds and stat_cmds hooks only).
# BIND and Kea are MPL-2.0: their license texts are in /usr/share/doc/<package>/copyright.

FROM debian:trixie-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
RUN PELAGOS_PYTHON=python3 packaging/build-tree.sh /out /src

FROM debian:trixie-slim
ARG KEA_SOURCE=isc
ARG PELAGOS_UID=8443
ARG PELAGOS_GID=8443
LABEL org.opencontainers.image.title="Pelagos all-in-one" \
      org.opencontainers.image.description="BIND 9, Kea and the Pelagos node in one image" \
      org.opencontainers.image.licenses="Apache-2.0 AND MPL-2.0" \
      org.opencontainers.image.source="https://github.com/NeySlim/pelagos"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 openssl ca-certificates curl gnupg util-linux libcap2-bin supervisor \
      bind9 bind9-utils bind9-dnsutils \
 && if [ "$KEA_SOURCE" = "isc" ]; then \
      curl -1sLf https://dl.cloudsmith.io/public/isc/kea-3-2/setup.deb.sh | distro=debian codename=trixie bash \
      && apt-get install -y --no-install-recommends isc-kea-dhcp4 isc-kea-dhcp6 isc-kea-dhcp-ddns isc-kea-hooks; \
    else \
      apt-get install -y --no-install-recommends kea-dhcp4-server kea-dhcp6-server kea-dhcp-ddns-server; \
    fi \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g "$PELAGOS_GID" pelagos \
 && useradd -u "$PELAGOS_UID" -g pelagos -G bind,_kea -d /var/lib/pelagos -s /usr/sbin/nologin -r pelagos \
 && install -d -o pelagos -g pelagos -m 0750 /etc/pelagos /var/lib/pelagos /run/pelagos \
 && install -d -o _kea -g _kea -m 0750 /run/kea /var/lib/kea /var/log/kea \
 && install -d -o root -g bind -m 2775 /var/cache/bind/pelagos \
 && install -d -o pelagos -g bind -m 2770 /etc/bind/pelagos \
 && for d in kea-dhcp4 kea-dhcp6 kea-dhcp-ddns; do \
      chmod 0755 /usr/sbin/$d && setcap cap_net_bind_service,cap_net_raw+ep /usr/sbin/$d; \
    done \
 && mkdir -p /usr/share/pelagos/seed \
 && cp -a /etc/bind /usr/share/pelagos/seed/bind \
 && rm -f /usr/share/pelagos/seed/bind/rndc.key \
 # /etc/bind starts empty so the entrypoint seeds the volume (named.conf, rndc-pelagos key).
 && find /etc/bind -mindepth 1 -delete \
 # session-keyfile of named (/run/named/session.key).
 && install -d -o bind -g bind -m 0775 /run/named
COPY --from=builder /out/opt/pelagos /opt/pelagos
COPY docker/allinone/named.conf /usr/share/pelagos/seed/bind/named.conf
COPY docker/kea/ /usr/share/pelagos/seed/kea-3/
COPY docker/kea-2.6/ /usr/share/pelagos/seed/kea-2.6/
COPY docker/allinone/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/entrypoint.sh /usr/local/bin/pelagos-entrypoint
COPY LICENSE NOTICE /usr/share/doc/pelagos/
RUN chmod 0755 /usr/local/bin/pelagos-entrypoint && ln -s /opt/pelagos/bin/pelagos /usr/bin/pelagos \
 && if [ "$KEA_SOURCE" = "isc" ]; then mv /usr/share/pelagos/seed/kea-3 /usr/share/pelagos/seed/kea; \
    else mv /usr/share/pelagos/seed/kea-2.6 /usr/share/pelagos/seed/kea; fi \
 && rm -rf /usr/share/pelagos/seed/kea-3 /usr/share/pelagos/seed/kea-2.6 \
 && rm -f /etc/kea/*.conf
# The daemons run as their own users (bind, _kea); pelagos belongs to both groups.
# The Kea directories are set image-wide, not only in supervisord.conf: `kea-dhcp4 -t` run by
# `pelagos import` through docker exec must accept the same socket paths as the daemons.
ENV PELAGOS_KEA_GID=_kea PELAGOS_BIND_GID=bind PELAGOS_BIND_UID=bind PYTHONUNBUFFERED=1 \
    KEA_DHCP6=false KEA_CONTROL_SOCKET_DIR=/run/kea KEA_PIDFILE_DIR=/run/kea KEA_LOCKFILE_DIR=/run/kea
VOLUME ["/etc/pelagos", "/var/lib/pelagos", "/etc/bind", "/var/cache/bind", "/etc/kea", "/var/lib/kea"]
EXPOSE 53/udp 53/tcp 67/udp 8443 8444
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD curl -fsk https://127.0.0.1:8443/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/pelagos-entrypoint"]
CMD ["allinone"]
