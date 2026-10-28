// SPDX-License-Identifier: Apache-2.0
// A zone in a URL path: no trailing dot, percent-encoded ("/" of RFC 2317 names included). Browsers
// drop a "." segment, even as %2E, so the root zone travels as "@", its origin (the API reads it so).
export const ROOT_SEGMENT = '@'

export function zoneSegment(zone) {
  const name = String(zone ?? '').replace(/\.$/, '')
  return name ? encodeURIComponent(name) : ROOT_SEGMENT
}

// The zone a decoded route parameter names.
export const zoneFromSegment = (segment) => (segment === ROOT_SEGMENT ? '.' : segment)
