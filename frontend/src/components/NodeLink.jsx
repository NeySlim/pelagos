// SPDX-License-Identifier: Apache-2.0
// A node by name: links to its own web UI when the peer has an http(s) web_url (new
// window), else to the nodes page. `short` shows the first label of the name only.
import { Link } from 'react-router-dom'
import { useNodePeers } from '../hooks/useNodeNames'
import { cn } from '../lib/utils'
import { shortNodeName } from '../lib/shortNodeName'

export function NodeLink({ nodeId, name, short = false, className, testId = 'node-link' }) {
  const peerOf = useNodePeers()
  const peer = peerOf({ nodeId, name })
  const full = peer?.name || name || nodeId
  if (!full) return null
  const label = short ? shortNodeName(full) : full
  const classes = cn('text-accent-primary hover:underline font-medium', className)
  const webUrl = peer?.web_url && /^https?:\/\//i.test(peer.web_url) ? peer.web_url : null
  if (webUrl) {
    return (
      <a href={webUrl} target="_blank" rel="noopener noreferrer" title={webUrl} className={classes} data-testid={testId}>
        {label}
      </a>
    )
  }
  return (
    <Link to="/nodes" title={label !== full ? full : undefined} className={classes} data-testid={testId}>
      {label}
    </Link>
  )
}

export default NodeLink
