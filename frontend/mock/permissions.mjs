// SPDX-License-Identifier: Apache-2.0
// Permission guard for the mock server (GET /install/permissions, section 7): every node's paths are
// writable until POST /_mock/permissions {node, broken: true} takes the zone folder away from one;
// a plan that writes there is then refused, and the path_access security plan gives it back.

const PATHS = [
  { path: '/etc/bind/cache/pelagos', kind: 'dir', engine: 'bind', purpose: 'zone_dir' },
  { path: '/etc/bind/pelagos', kind: 'dir', engine: 'bind', purpose: 'include_dir' },
  { path: '/var/lib/pelagos/backups/bind', kind: 'dir', engine: 'bind', purpose: 'backup_dir' },
]
const ZONE_DIR = PATHS[0].path
export const PATH_FINDING = `bind:path_access:${ZONE_DIR}`
const COMMAND = `install -d -o bind -g bind -m 2775 ${ZONE_DIR}`

function failed(p) {
  const message = {
    key: 'permission.finding',
    params: {
      path: p.path,
      what: { key: `permission.purpose.${p.purpose}`, params: {} },
      probed: '/etc/bind/cache',
      owner: 'bind',
      group: 'bind',
      mode: '0755',
      missing: { key: 'permission.problem.denied.dir', params: {} },
      command: COMMAND,
    },
  }
  return {
    ...p, ok: false, route: '', problem: 'denied', error: 'Permission denied', probed: '/etc/bind/cache', exists: false,
    owner: 'bind', group: 'bind', mode: '0755', command: COMMAND, remediable: true,
    fix: { action: 'create_dir', path: ZONE_DIR, owner: 'bind', group: 'bind' },
    finding_id: PATH_FINDING, message,
    text: `Zone folder ${p.path}: cannot be created: no write permission on the parent folder (now bind:bind 0755 on /etc/bind/cache); fix: ${COMMAND}`,
  }
}

export function permissionChecks(state, nodeId) {
  const broken = (state.permissionsBroken ||= new Set()).has(nodeId)
  return PATHS.map((p) => (broken && p.path === ZONE_DIR ? failed(p) : { ...p, ok: true, route: 'direct', exists: true, owner: 'bind', group: 'bind', mode: '2775', probed: p.path }))
}

// The validations of a BIND plan on `targets`: one refusal per node whose zone folder is broken.
export function guardValidations(state, targets, tool) {
  const name = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const bad = targets.filter((id) => (state.permissionsBroken ||= new Set()).has(id))
  if (!bad.length) return null
  const nodes = bad.map((id) => ({ key: 'permission.node', params: { node: name(id), items: { join: [failed(PATHS[0]).message], sep: '; ' } } }))
  const message = { key: 'permission.plan_refused', params: { nodes: { join: nodes, sep: ' | ' } } }
  const text = `plan refused, Pelagos cannot write paths this plan needs: ${bad.map((id) => `${name(id)}: ${failed(PATHS[0]).text}`).join(' | ')}`
  return {
    message, text,
    validations: [
      ...targets.map((node_id) => ({ ok: true, tool, output: '', node_id })),
      ...bad.map((node_id) => ({ ok: false, tool: 'permissions', output: text, output_message: message, node_id })),
    ],
  }
}

export function permissionsHandlers(state, { invalid }) {
  return {
    'GET /install/permissions': ({ query }) => {
      const node = query.get('node') || state.selfId
      if (!state.nodes.some((n) => n.peer.id === node)) throw invalid('node', 'a node id')
      return { node_id: node, available: true, checks: permissionChecks(state, node) }
    },
  }
}
