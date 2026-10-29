// SPDX-License-Identifier: Apache-2.0
// One function per endpoint of docs/architecture.md section 17, grouped by area.
// Bodies and query parameters follow the spec literally; every function returns
// the parsed JSON (or null for 204). Plans come back as Plan objects and are
// applied through api.plans.apply(id, confirm).
import { apiClient, buildQueryString, API_BASE_URL } from './apiClient'
import { zoneSegment } from '../lib/zonePath'

const enc = encodeURIComponent
const zonePath = zoneSegment

export const meta = {
  health: () => apiClient.get('/health'),
  version: () => apiClient.get('/version'),
  capabilities: () => apiClient.get('/capabilities'),
}

export const auth = {
  login: (username, password, totp_code) =>
    apiClient.post('/auth/login', totp_code ? { username, password, totp_code } : { username, password }),
  logout: () => apiClient.post('/auth/logout'),
  session: () => apiClient.get('/auth/session'),
  changePassword: (current_password, new_password) =>
    apiClient.post('/auth/password', { current_password, new_password }),
  totpEnroll: () => apiClient.post('/auth/totp/enroll'),
  totpConfirm: (code) => apiClient.post('/auth/totp/confirm', { code }),
  totpDisable: (password) => apiClient.delete('/auth/totp', { password }),
  // Security keys and passkeys (section 16): options JSON in, PublicKeyCredential JSON out.
  webauthnSite: () => apiClient.get('/auth/webauthn'),
  passkeyOptions: () => apiClient.post('/auth/webauthn/login/options'),
  webauthnLogin: (ceremony, credential) => apiClient.post('/auth/webauthn/login/verify', { ceremony, credential }),
  keys: () => apiClient.get('/auth/webauthn/credentials'),
  keyRegisterOptions: () => apiClient.post('/auth/webauthn/register/options'),
  keyRegister: (ceremony, credential, name) => apiClient.post('/auth/webauthn/register/verify', { ceremony, credential, name }),
  keyRename: (id, name) => apiClient.patch(`/auth/webauthn/credentials/${enc(id)}`, { name }),
  keyRemove: (id, password) => apiClient.delete(`/auth/webauthn/credentials/${enc(id)}`, { password }),
  // API tokens (section 16): creation needs a fresh second factor; the secret comes back once.
  tokens: () => apiClient.get('/auth/tokens'),
  tokenChallenge: () => apiClient.post('/auth/tokens/challenge'),
  tokenCreate: (body) => apiClient.post('/auth/tokens', body),
  tokenRevoke: (id) => apiClient.delete(`/auth/tokens/${enc(id)}`),
}

export const account = {
  getPreferences: () => apiClient.get('/account/preferences'),
  updatePreferences: (prefs) => apiClient.put('/account/preferences', prefs),
}

export const nodes = {
  list: () => apiClient.get('/nodes'),
  self: () => apiClient.get('/nodes/self'),
  get: (id) => apiClient.get(`/nodes/${enc(id)}`),
  enrollToken: (ttl_seconds) => apiClient.post('/nodes/enroll-token', ttl_seconds ? { ttl_seconds } : {}),
  remove: (id) => apiClient.delete(`/nodes/${enc(id)}`),
  sync: (id) => apiClient.post(`/nodes/${enc(id)}/sync`),
  replication: () => apiClient.get('/nodes/replication'),
}

export const dashboard = {
  summary: () => apiClient.get('/dashboard/summary'),
  getLayout: () => apiClient.get('/dashboard/layout'),
  saveLayout: (layout) => apiClient.put('/dashboard/layout', { layout }),
}

export const dns = {
  instances: () => apiClient.get('/dns/instances'),
  zones: (params) => apiClient.get(`/dns/zones${buildQueryString(params)}`),
  zone: (zone, view) => apiClient.get(`/dns/zones/${zonePath(zone)}${buildQueryString({ view })}`),
  zonePlan: (change, node_ids) => apiClient.post('/dns/zones/plan', node_ids?.length ? { change, node_ids } : { change }),
  // node_ids: every node that is to hold the zone as a secondary of its primary node.
  secondariesPlan: (zone, view, node_ids) =>
    apiClient.post(`/dns/zones/${zonePath(zone)}/secondaries/plan`, { node_ids, ...(view ? { view } : {}) }),
  records: (zone, params) => apiClient.get(`/dns/zones/${zonePath(zone)}/records${buildQueryString(params)}`),
  // ptr: { sync, delete, reverse_view? } also writes the PTR of the A/AAAA changes in the same plan.
  recordsPlan: (zone, changes, view, ptr) =>
    apiClient.post(`/dns/zones/${zonePath(zone)}/records/plan`, { ...(view ? { view } : {}), changes, ...(ptr ? { ptr } : {}) }),
  ptrCoverage: (body) => apiClient.post('/dns/ptr/coverage', body),
  ptrOrphans: () => apiClient.get('/dns/ptr/orphans'),
  ptrOrphansPlan: (body) => apiClient.post('/dns/ptr/orphans/plan', body),
  retransfer: (zone, node_id, view) =>
    apiClient.post(`/dns/zones/${zonePath(zone)}/retransfer`, { node_id, ...(view ? { view } : {}) }),
  notify: (zone, body = {}) => apiClient.post(`/dns/zones/${zonePath(zone)}/notify`, body),
  reload: (zone, body = {}) => apiClient.post(`/dns/zones/${zonePath(zone)}/reload`, body),
  dnssec: (zone, params) => apiClient.get(`/dns/zones/${zonePath(zone)}/dnssec${buildQueryString(params)}`),
  config: (node_id) => apiClient.get(`/dns/config${buildQueryString({ node_id })}`),
  configPlan: (changes, node_ids) =>
    apiClient.post('/dns/config/plan', node_ids ? { node_ids, changes } : { changes }),
  handover: () => apiClient.get('/dns/handover'),
  keys: () => apiClient.get('/dns/keys'),
  keySecret: (name) => apiClient.get(`/dns/keys/${enc(name)}/secret`),
  keysPlan: (change) => apiClient.post('/dns/keys/plan', { change }),
  acls: () => apiClient.get('/dns/acls'),
  aclsPlan: (change) => apiClient.post('/dns/acls/plan', { change }),
  resolver: () => apiClient.get('/dns/resolver'),
  resolverPlan: (settings) => apiClient.post('/dns/resolver/plan', settings),
  rpz: () => apiClient.get('/dns/rpz'),
  rpzOverview: () => apiClient.get('/dns/rpz/overview'),
  rpzCatalog: () => apiClient.get('/dns/rpz/catalog'),
  rpzSetCategory: (category, body) => apiClient.put(`/dns/rpz/categories/${enc(category)}`, body),
  rpzClearCategory: (category) => apiClient.delete(`/dns/rpz/categories/${enc(category)}`),
  rpzSetSubscription: (id, body) => apiClient.put(`/dns/rpz/subscriptions/${enc(id)}`, body),
  rpzDeleteSubscription: (id) => apiClient.delete(`/dns/rpz/subscriptions/${enc(id)}`),
  rpzSetOrder: (order) => apiClient.put('/dns/rpz/order', { order }),
  rpzPlan: () => apiClient.post('/dns/rpz/plan'),
  rpzEstimate: (body) => apiClient.post('/dns/rpz/estimate', body),
  rpzRefresh: (id, acceptShrink = false) =>
    apiClient.post('/dns/rpz/refresh', id ? { id, ...(acceptShrink ? { accept_shrink: true } : {}) } : {}),
  rpzWhy: (domain, node_id) => apiClient.get(`/dns/rpz/why${buildQueryString({ domain, node_id })}`),
  rpzActivity: () => apiClient.get('/dns/rpz/activity'),
  rpzAllow: (domain, note) => apiClient.post('/dns/rpz/allow', { domain, note }),
  rpzDisallow: (domain) => apiClient.delete(`/dns/rpz/allow${buildQueryString({ domain })}`),
  rpzExempt: (cidr, note) => apiClient.post('/dns/rpz/exempt', { cidr, note }),
  rpzUnexempt: (cidr) => apiClient.delete(`/dns/rpz/exempt${buildQueryString({ cidr })}`),
  catalogZones: () => apiClient.get('/dns/catalog-zones'),
  catalogMemberPlan: (zone, body) => apiClient.post(`/dns/catalog-zones/${zonePath(zone)}/members/plan`, body),
  dnssecPolicies: () => apiClient.get('/dns/dnssec/policies'),
  dnssecPoliciesPlan: (change) => apiClient.post('/dns/dnssec/policies/plan', { change }),
  dnssecPlan: (zone, body) => apiClient.post(`/dns/zones/${zonePath(zone)}/dnssec/plan`, body),
  stats: (node_id) => apiClient.get(`/dns/stats${buildQueryString({ node_id })}`),
}

// `family` is 'v4' or 'v6' (v6 paths answer 404 module_disabled when the module is off).
export const dhcp = {
  servers: (family) => apiClient.get(`/dhcp/${family}/servers`),
  subnets: (family, params) => apiClient.get(`/dhcp/${family}/subnets${buildQueryString(params)}`),
  subnet: (family, id) => apiClient.get(`/dhcp/${family}/subnets/${enc(id)}`),
  subnetPlan: (family, change) => apiClient.post(`/dhcp/${family}/subnets/plan`, { change }),
  sharedNetworks: (family, node_id) => apiClient.get(`/dhcp/${family}/shared-networks${buildQueryString({ node_id })}`),
  sharedNetworkPlan: (family, change) => apiClient.post(`/dhcp/${family}/shared-networks/plan`, { change }),
  clientClasses: (family, node_id) => apiClient.get(`/dhcp/${family}/client-classes${buildQueryString({ node_id })}`),
  clientClassPlan: (family, change) => apiClient.post(`/dhcp/${family}/client-classes/plan`, { change }),
  options: (family, node_id) => apiClient.get(`/dhcp/${family}/options${buildQueryString({ node_id })}`),
  optionsPlan: (family, changes) => apiClient.post(`/dhcp/${family}/options/plan`, { changes }),
  reservations: (family, params) => apiClient.get(`/dhcp/${family}/reservations${buildQueryString(params)}`),
  reservationPlan: (family, change) => apiClient.post(`/dhcp/${family}/reservations/plan`, { change }),
  leases: (family, params) => apiClient.get(`/dhcp/${family}/leases${buildQueryString(params)}`),
  recentLeases: (family, params) => apiClient.get(`/dhcp/${family}/leases/recent${buildQueryString(params)}`),
  lease: (family, ip) => apiClient.get(`/dhcp/${family}/leases/${enc(ip)}`),
  // node_id: the node holding the copy to delete (default: every node holding the lease).
  leaseDeletePlan: (family, ip, node_id) =>
    apiClient.post(`/dhcp/${family}/leases/${enc(ip)}/delete/plan`, node_id ? { node_id } : undefined),
  utilization: (family, node_id) => apiClient.get(`/dhcp/${family}/utilization${buildQueryString({ node_id })}`),
  stats: (family, node_id) => apiClient.get(`/dhcp/${family}/stats${buildQueryString({ node_id })}`),
  ha: (family) => apiClient.get(`/dhcp/${family}/ha`),
  haMaintenancePlan: (family, node_id, action) =>
    apiClient.post(`/dhcp/${family}/ha/maintenance/plan`, { node_id, action }),
  // Restart the HA service of each terminated server in turn; server_name narrows to its relationship.
  haRepairPlan: (family, server_name) => apiClient.post(`/dhcp/${family}/ha/repair/plan`, server_name ? { server_name } : {}),
  // The relationship written on every node of it: { mode, servers: [{ name, url, role, node_id? }] }, or { remove: true }.
  haSetupPlan: (family, body) => apiClient.post(`/dhcp/${family}/ha/setup/plan`, body),
  haTransitions: (family, params) => apiClient.get(`/dhcp/${family}/ha/transitions${buildQueryString(params)}`),
  servicePlan: (family, node_id, enable) => apiClient.post(`/dhcp/${family}/service/plan`, { node_id, enable }),
  ddns: (family) => apiClient.get(`/dhcp/${family}/ddns`),
  ddnsPlan: (family, changes) => apiClient.post(`/dhcp/${family}/ddns/plan`, { changes }),
  hooks: (family) => apiClient.get(`/dhcp/${family}/hooks`),
  hooksPlan: (family, changes) => apiClient.post(`/dhcp/${family}/hooks/plan`, { changes }),
  config: (family, node_id) => apiClient.get(`/dhcp/${family}/config${buildQueryString({ node_id })}`),
  // node_id: the node whose configuration was loaded; the replace targets that node only.
  configPlan: (family, config, node_ids, node_id) =>
    apiClient.post(`/dhcp/${family}/config/plan`, { config, ...(node_ids ? { node_ids } : {}), ...(node_id ? { node_id } : {}) }),
  // Section 9: does the file on disk say what Kea runs; adopt one side when it does not.
  configFile: (family) => apiClient.get(`/dhcp/${family}/config/file`),
  // node_id: the node that holds the file (default this node); a peer builds its own plan.
  adoptPlan: (family, source, node_id) => apiClient.post(`/dhcp/${family}/config/adopt/plan`, { source, ...(node_id ? { node_id } : {}) }),
}

export const d2 = {
  servers: () => apiClient.get('/dhcp/d2/servers'),
  stats: (node_id) => apiClient.get(`/dhcp/d2/stats${buildQueryString({ node_id })}`),
  config: (node_id) => apiClient.get(`/dhcp/d2/config${buildQueryString({ node_id })}`),
  configPlan: (config, node_ids, node_id) =>
    apiClient.post('/dhcp/d2/config/plan', { config, ...(node_ids ? { node_ids } : {}), ...(node_id ? { node_id } : {}) }),
  configFile: () => apiClient.get('/dhcp/d2/config/file'),
  adoptPlan: (source, node_id) => apiClient.post('/dhcp/d2/config/adopt/plan', { source, ...(node_id ? { node_id } : {}) }),
}

export const hosts = {
  list: (params) => apiClient.get(`/hosts${buildQueryString(params)}`),
  get: (key) => apiClient.get(`/hosts/${enc(key)}`),
  plan: (body) => apiClient.post('/hosts/plan', body),
}

export const plans = {
  get: (id) => apiClient.get(`/plans/${enc(id)}`),
  apply: (id, confirm = false) => apiClient.post(`/plans/${enc(id)}/apply`, { confirm }),
  rollback: (id) => apiClient.post(`/plans/${enc(id)}/rollback`),
  remove: (id) => apiClient.delete(`/plans/${enc(id)}`),
}

export const jobs = {
  get: (id) => apiClient.get(`/jobs/${enc(id)}`),
}

export const alerts = {
  list: (params) => apiClient.get(`/alerts${buildQueryString(params)}`),
  summary: () => apiClient.get('/alerts/summary'),
  ack: (id, comment) => apiClient.post(`/alerts/${enc(id)}/ack`, comment ? { comment } : {}),
  runConsistency: () => apiClient.post('/alerts/consistency/run'),
  exceptions: (params) => apiClient.get(`/alerts/exceptions${buildQueryString(params)}`),
  addException: (body) => apiClient.post('/alerts/exceptions', body),
  revokeException: (id) => apiClient.delete(`/alerts/exceptions/${enc(id)}`),
}

export const series = {
  pools: (params) => apiClient.get(`/series/pools${buildQueryString(params)}`),
  serials: (params) => apiClient.get(`/series/serials${buildQueryString(params)}`),
  haTransitions: (params) => apiClient.get(`/series/ha-transitions${buildQueryString(params)}`),
}

export const audit = {
  list: (params) => apiClient.get(`/audit${buildQueryString(params)}`),
  get: (id) => apiClient.get(`/audit/${enc(id)}`),
  // NDJSON stream: returned as text, one AuditEntry per line.
  exportEntries: (params) => apiClient.get(`/audit/export${buildQueryString(params)}`, { responseType: 'text' }),
  exportUrl: (params) => `${API_BASE_URL}/audit/export${buildQueryString(params)}`,
}

export const advanced = {
  bindGrammar: () => apiClient.get('/advanced/bind/grammar'),
  bindTree: (node_id) => apiClient.get(`/advanced/bind/tree${buildQueryString({ node_id })}`),
  keaSchema: (family) => apiClient.get(`/advanced/kea/${family}/schema`),
  history: (params) => apiClient.get(`/advanced/history${buildQueryString(params)}`),
  historyEntry: (id) => apiClient.get(`/advanced/history/${enc(id)}`),
}

// Runtime operations: family is v4, v6 or d2; params are the operation's typed parameters.
export const ops = {
  bindCatalog: () => apiClient.get('/dns/ops'),
  bindRun: ({ op, params, node_id, confirm }) => apiClient.post('/dns/ops', { op, params, node_id, confirm }),
  keaCatalog: (family, node_id) => apiClient.get(`/dhcp/${family}/ops${buildQueryString({ node_id })}`),
  keaRun: (family, { command, params, node_id, confirm }) =>
    apiClient.post(`/dhcp/${family}/ops`, { command, params, node_id, confirm }),
}

export const install = {
  detect: () => apiClient.get('/install/detect'),
  plan: (body) => apiClient.post('/install/plan', body),
  importPlan: (engines) => apiClient.post('/install/import/plan', { engines }),
  security: (node) => apiClient.get(`/install/security${node ? buildQueryString({ node }) : ''}`),
  // A list of finding ids of this node, or a selection {node id: [finding ids]} across nodes.
  securityPlan: (selection) => apiClient.post('/install/security/plan', Array.isArray(selection) ? { finding_ids: selection } : { selection }),
  // The nftables guard of the Kea HA listeners of a node, and a plan that sets its allowed addresses.
  haGuard: (node) => apiClient.get(`/install/security/ha-guard${node ? buildQueryString({ node }) : ''}`),
  haGuardPlan: (node, peers) => apiClient.post('/install/security/ha-guard/plan', node ? { node, peers } : { peers }),
  // Kea HA TLS on every peer: the switch, or the renewal of the certificates when it already is TLS.
  haTlsPlan: () => apiClient.post('/install/security/ha-tls/plan', {}),
  // Paths the services of a node must create or write, probed in its unit now (permission guard).
  permissions: (node) => apiClient.get(`/install/permissions${node ? buildQueryString({ node }) : ''}`),
}

export const admin = {
  users: () => apiClient.get('/admin/users'),
  createUser: (body) => apiClient.post('/admin/users', body),
  user: (id) => apiClient.get(`/admin/users/${enc(id)}`),
  updateUser: (id, body) => apiClient.put(`/admin/users/${enc(id)}`, body),
  deleteUser: (id) => apiClient.delete(`/admin/users/${enc(id)}`),
  resetPassword: (id, password) => apiClient.post(`/admin/users/${enc(id)}/reset-password`, { password }),
  clearTotp: (id) => apiClient.delete(`/admin/users/${enc(id)}/totp`),
  userKeys: (id) => apiClient.get(`/admin/users/${enc(id)}/webauthn`),
  removeUserKeys: (id) => apiClient.delete(`/admin/users/${enc(id)}/webauthn`),
  removeUserKey: (id, keyId) => apiClient.delete(`/admin/users/${enc(id)}/webauthn/${enc(keyId)}`),
  webauthn: () => apiClient.get('/admin/webauthn'),
  tokens: () => apiClient.get('/admin/tokens'),
  revokeToken: (id) => apiClient.delete(`/admin/tokens/${enc(id)}`),
  roles: () => apiClient.get('/admin/roles'),
  createRole: (role) => apiClient.post('/admin/roles', role),
  updateRole: (name, body) => apiClient.put(`/admin/roles/${enc(name)}`, body),
  deleteRole: (name) => apiClient.delete(`/admin/roles/${enc(name)}`),
  permissions: () => apiClient.get('/admin/permissions'),
  settings: () => apiClient.get('/admin/settings'),
  updateSettings: (partial) => apiClient.put('/admin/settings', partial),
  settingsSchema: () => apiClient.get('/admin/settings/schema'),
  modules: () => apiClient.get('/admin/modules'),
  updateModules: (partial) => apiClient.put('/admin/modules', partial),
}

// Web UI certificates of every node (Administration > Certificates).
export const certs = {
  overview: () => apiClient.get('/admin/certificates'),
  node: (id) => apiClient.get(`/admin/certificates/${enc(id)}`),
  setSource: (id, body) => apiClient.put(`/admin/certificates/${enc(id)}/source`, body),
  setCluster: (body) => apiClient.put('/admin/certificates/cluster', body),
  clearCluster: () => apiClient.delete('/admin/certificates/cluster'),
  renew: (id) => apiClient.post(`/admin/certificates/${enc(id)}/renew`),
  request: (id, body) => apiClient.post(`/admin/certificates/${enc(id)}/request`, body),
  dropRequest: (id) => apiClient.delete(`/admin/certificates/${enc(id)}/request`),
  check: (id, body) => apiClient.post(`/admin/certificates/${enc(id)}/check`, body),
  upload: (id, body) => apiClient.post(`/admin/certificates/${enc(id)}/upload`, body),
  selfSigned: (id) => apiClient.post(`/admin/certificates/${enc(id)}/self-signed`),
  testUcm: (body) => apiClient.post('/admin/certificates/test/ucm', body),
  testAcme: (body) => apiClient.post('/admin/certificates/test/acme', body),
  testDns: (body) => apiClient.post('/admin/certificates/test/dns', body),
  dns01Plan: (body) => apiClient.post('/admin/certificates/dns01/plan', body),
}

// Outgoing alert notifications (Administration > Notifications, section 22). Secrets go in
// `secrets: {name: value|null}` and come back as booleans only.
export const notifications = {
  overview: () => apiClient.get('/admin/notifications'),
  createChannel: (channel) => apiClient.post('/admin/notifications/channels', channel),
  updateChannel: (id, partial) => apiClient.put(`/admin/notifications/channels/${enc(id)}`, partial),
  deleteChannel: (id) => apiClient.delete(`/admin/notifications/channels/${enc(id)}`),
  // {channel_id} for a saved channel, or an unsaved channel (its `scope` names the stored secrets).
  test: (body) => apiClient.post('/admin/notifications/test', body),
  setOrder: (node_ids) => apiClient.put('/admin/notifications/order', { node_ids }),
  mute: (until, comment) => apiClient.put('/admin/notifications/mute', { until, comment }),
  unmute: () => apiClient.delete('/admin/notifications/mute'),
  history: (params) => apiClient.get(`/admin/notifications/history${buildQueryString(params)}`),
}

// Encrypted archives and restore (Administration > Backups, section 23).
export const archives = {
  overview: () => apiClient.get('/admin/archives'),
  // Partial [settings.archives]: schedule, retention, checks (refused: scheduling with no recipient).
  updateSettings: (partial) => apiClient.put('/admin/archives/settings', partial),
  createDestination: (destination) => apiClient.post('/admin/archives/destinations', destination),
  updateDestination: (id, partial) => apiClient.put(`/admin/archives/destinations/${enc(id)}`, partial),
  deleteDestination: (id) => apiClient.delete(`/admin/archives/destinations/${enc(id)}`),
  testDestination: (body) => apiClient.post('/admin/archives/destinations/test', body),
  run: (node_ids) => apiClient.post('/admin/archives/run', node_ids ? { node_ids } : {}),
  list: (params) => apiClient.get(`/admin/archives/list${buildQueryString(params)}`),
  downloadUrl: (id) => `${API_BASE_URL}/admin/archives/${enc(id)}/download`,
  download: (id) => apiClient.get(`/admin/archives/${enc(id)}/download`, { responseType: 'blob' }),
  // A .tar.gz.age file made elsewhere, with an identity that opens it when the cluster's do not.
  upload: (file, identity) => {
    const form = new FormData()
    if (file) form.append('file', file)
    if (identity) form.append('identity', identity)
    return apiClient.post('/admin/archives/upload', form)
  },
  // {op: generate|rotate|add_recipient|remove_recipient|prune_retired, recipient?, label?, password?}
  identity: (body) => apiClient.post('/admin/archives/identity', body),
  // {identity?, target_node_id?, substitute?, ha_tls?}
  inspect: (id, body) => apiClient.post(`/admin/archives/${enc(id)}/inspect`, body || {}),
  restorePlan: (id, body) => apiClient.post(`/admin/archives/${enc(id)}/restore/plan`, body),
}

// DDNS without a single point of failure (DHCP > DDNS > Failover, section 24).
export const ddnsFailover = {
  resilience: () => apiClient.get('/dhcp/ddns/resilience'),
  preparePlan: (zones) => apiClient.post('/dhcp/ddns/resilience/plan', zones ? { zones } : {}),
  failoverPlan: (to_node_id, zones) => apiClient.post('/dhcp/ddns/failover/plan', zones ? { to_node_id, zones } : { to_node_id }),
  switchoverPlan: (to_node_id, zones) => apiClient.post('/dhcp/ddns/switchover/plan', zones ? { to_node_id, zones } : { to_node_id }),
  // {from?, to?, family?, limit?}
  replayPlan: (body = {}) => apiClient.post('/dhcp/ddns/replay/plan', body),
}

// Resolver health and the temporary forwarder fallback (DNS > Resolver, section 25).
export const resolverHealth = {
  health: (node_id) => apiClient.get(`/dns/resolver/health${buildQueryString({ node_id })}`),
  // {node_id, metric, from, to, step}
  series: (params) => apiClient.get(`/series/resolver${buildQueryString(params)}`),
  // {forwarders, forward: first|only, node_ids?, hours, preset?, tls_name?}
  fallbackPlan: (body) => apiClient.post('/dns/resolver/fallback/plan', body),
  returnPlan: () => apiClient.post('/dns/resolver/fallback/return/plan', {}),
  extend: (hours) => apiClient.put('/dns/resolver/fallback', { hours }),
}

// Kea 2.6 to 3.x migration, read-only analysis (Installation > Kea migration, section 26).
export const keaMigration = {
  overview: () => apiClient.get('/install/kea-migration'),
  // {series, source, node_ids?}
  analyze: (body) => apiClient.post('/install/kea-migration/analyze', body),
}

// Observed IPv6 addresses (Hosts > IPv6, Administration > IPv6 observation, section 27).
export const ipv6 = {
  // {filter: missing_aaaa|missing_ptr|stale|unknown|random_mac, zone, page, per_page}
  hosts: (params) => apiClient.get(`/hosts/ipv6${buildQueryString(params)}`),
  settings: () => apiClient.get('/admin/ipv6'),
  // {prefixes}
  update: (body) => apiClient.put('/admin/ipv6', body),
}

export const api = {
  meta, auth, account, nodes, dashboard, dns, dhcp, d2, hosts, plans, jobs,
  alerts, series, audit, advanced, install, admin, certs, ops, notifications, archives, ddnsFailover,
  resolverHealth, keaMigration, ipv6,
}

export default api
