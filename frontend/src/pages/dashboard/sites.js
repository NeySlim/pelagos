// SPDX-License-Identifier: Apache-2.0
// Sites are shown once the cluster spans at least two (the label is optional, `Peer.site`).
export const spansSites = (nodes) => new Set((nodes || []).map((n) => n.peer?.site).filter(Boolean)).size >= 2
