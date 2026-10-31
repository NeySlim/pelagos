#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Container images of a release, in two steps run by the release workflows.
#
# Usage: release-images.sh candidates REGISTRY VERSION DIGESTS
#        release-images.sh promote [--latest] REGISTRY VERSION DIGESTS
#   candidates  push the tested local images <image>:release-<arch> as REGISTRY/<image>:VERSION-<arch>
#               only, and write "<image> <arch> <digest>" lines to DIGESTS
#   promote     check that every VERSION-<arch> tag still holds the digest of DIGESTS, then point
#               REGISTRY/<image>:VERSION (and latest with --latest) at those digests, no rebuild
# Images: pelagos and pelagos-allinone; arches: amd64 and arm64. Needs docker buildx and jq.
set -euo pipefail

images=(pelagos pelagos-allinone)
arches=(amd64 arm64)
die() { echo "release-images: $*" >&2; exit 1; }

# Registry digest of a tag or digest reference.
digest_of() {
  docker buildx imagetools inspect --format '{{json .Manifest}}' "$1" | jq -er .digest
}

# The single-platform manifests a reference stands for (itself, or the children of an index
# without attestations), as "<digest> <os>/<arch>" lines.
platforms_of() {
  local raw
  raw="$(docker buildx imagetools inspect --raw "$1")"
  if jq -e 'has("manifests")' <<<"$raw" >/dev/null; then
    jq -r '.manifests[] | select(.platform.os != "unknown") | "\(.digest) \(.platform.os)/\(.platform.architecture)"' <<<"$raw"
  else
    local config
    config="$(docker buildx imagetools inspect --format '{{json .Image}}' "$1")"
    printf '%s %s\n' "$(digest_of "$1")" "$(jq -r '"\(.os)/\(.architecture)"' <<<"$config")"
  fi
}

candidates() {
  local registry="$1" version="$2" out="$3" image arch ref
  : >"$out"
  for image in "${images[@]}"; do
    for arch in "${arches[@]}"; do
      ref="$registry/$image:$version-$arch"
      docker tag "$image:release-$arch" "$ref"
      docker push --quiet "$ref" >/dev/null
      printf '%s %s %s\n' "$image" "$arch" "$(digest_of "$ref")" >>"$out"
    done
  done
  cat "$out"
}

promote() {
  local latest=false
  [[ "${1:-}" == --latest ]] && { latest=true; shift; }
  local registry="$1" version="$2" digests="$3" image arch want have refs tags expected got
  for image in "${images[@]}"; do
    refs=() expected=""
    for arch in "${arches[@]}"; do
      want="$(awk -v i="$image" -v a="$arch" '$1 == i && $2 == a { print $3 }' "$digests")"
      [[ "$want" =~ ^sha256:[0-9a-f]{64}$ ]] || die "no digest for $image $arch in $digests"
      have="$(digest_of "$registry/$image:$version-$arch")" \
        || die "candidate $registry/$image:$version-$arch is missing"
      [[ "$have" == "$want" ]] \
        || die "$registry/$image:$version-$arch is $have, not the tested $want"
      platforms_of "$registry/$image@$want" | grep -q " linux/$arch\$" \
        || die "$registry/$image@$want is not a linux/$arch image"
      refs+=("$registry/$image@$want")
      expected+="$(platforms_of "$registry/$image@$want")"$'\n'
    done
    tags=(-t "$registry/$image:$version")
    $latest && tags+=(-t "$registry/$image:latest")
    docker buildx imagetools create "${tags[@]}" "${refs[@]}"
    # The new index must list exactly the tested manifests, and latest must be that index.
    got="$(platforms_of "$registry/$image:$version" | sort)"
    [[ "$got" == "$(sort <<<"${expected%$'\n'}")" ]] \
      || die "$registry/$image:$version does not list the tested manifests: $got"
    if $latest; then
      [[ "$(digest_of "$registry/$image:latest")" == "$(digest_of "$registry/$image:$version")" ]] \
        || die "$registry/$image:latest is not $version"
    fi
    echo "$registry/$image:$version$($latest && echo ' and latest') -> $(digest_of "$registry/$image:$version")"
  done
}

case "${1:-}" in
  candidates) shift; [[ $# -eq 3 ]] || die "usage: candidates REGISTRY VERSION DIGESTS"; candidates "$@" ;;
  promote) shift; [[ $# -ge 3 ]] || die "usage: promote [--latest] REGISTRY VERSION DIGESTS"; promote "$@" ;;
  -h|--help) sed -n '3,11p' "$0" ;;
  *) die "usage: release-images.sh candidates|promote ... (--help)" ;;
esac
