#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Starts a Kea daemon whose control socket is $1. Kea 2.x creates it 0750 (umask 0027): the
# pelagos user, in the Kea group, needs group write to connect. Kea 3.x creates it 0770.
sock="$1"
shift
rm -f "$sock"
(for _ in $(seq 1 100); do if [ -S "$sock" ]; then exec chmod g+w "$sock"; fi; sleep 0.1; done) &
exec "$@"
