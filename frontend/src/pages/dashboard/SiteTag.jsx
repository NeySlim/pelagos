// SPDX-License-Identifier: Apache-2.0
// The site label of a node, small, next to its name.
export function SiteTag({ node }) {
  const site = node.peer?.site
  if (!site) return null
  return (
    <span className="shrink-0 rounded border border-border px-1 text-2xs font-normal text-text-tertiary" title={site} data-testid="node-site">
      {site}
    </span>
  )
}

export default SiteTag
