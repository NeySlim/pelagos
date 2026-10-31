// SPDX-License-Identifier: Apache-2.0
// A node by name: links to its own web UI when the peer has a web_url (new window),
// else to the nodes page. `short` shows the first label of the name only.
import { Link } from 'react-router-dom'
import { useNodePeers } from '../hooks/useNodeNames'
import { cn } from '../lib/utils'

function shortNodeName(name) {
  if (!name) return name
  return /^[0-9.:[\]]+$/.test(name) ? name : name.split('.')[0]
}

export function NodeLink({ nodeId, name, short = false, className, testId = 'node-link' }) {
  const peerOf = useNodePeers()
  const peer = peerOf({ nodeId, name })
  const full = peer?.name || name || nodeId
  if (!full) return null
  const label = short ? shortNodeName(full) : full
  const classes = cn('text-accent-primary hover:underline font-medium', className)
  if (peer?.web_url) {
    return (
      <a href={peer.web_url} target="_blank" rel="noopener noreferrer" title={peer.web_url} className={classes} data-testid={testId}>
        {label}
      </a>
    )
  }
  return (
    <Link to="/nodes" title={short && label !== full ? full : '/nodes'} className={classes} data-testid={testId}>
      {label}
    </Link>
  )
}

export default NodeLink
