// SPDX-License-Identifier: Apache-2.0
// Sample cluster for the mock server: two nodes (ns1, ns2) running BIND, Kea 4/6
// and D2 in hot-standby, documentation address space only. Shapes follow
// docs/architecture.md sections 4 and 17. createState() returns a fresh copy so
// tests and the server never share mutations.

const NOW = Date.now()
export const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
const ago = (seconds) => iso(NOW - seconds * 1000)

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
let ulidCounter = 0
// Time-sortable 26-char id; deterministic enough for a mock.
export function ulid(ms = Date.now()) {
  let time = ms
  let out = ''
  for (let i = 0; i < 10; i += 1) {
    out = CROCKFORD[time % 32] + out
    time = Math.floor(time / 32)
  }
  ulidCounter += 1
  let rand = ''
  let seed = ulidCounter * 2654435761
  for (let i = 0; i < 16; i += 1) {
    rand += CROCKFORD[seed % 32]
    seed = Math.floor(seed / 32) + (i + 1) * 7919
  }
  return out + rand
}

const NODE_IDS = { ns1: '01JB0000000000000000NS1AAA', ns2: '01JB0000000000000000NS2BBB' }
export const SELF_ID = NODE_IDS.ns1

function peer(name, id) {
  return {
    id,
    name,
    url: `https://${name}.example.lan:8444`,
    web_url: `https://${name}.example.lan:8443`,
    cert_fingerprint: name === 'ns1' ? 'a3f1c2'.padEnd(64, '0') : 'b7e9d4'.padEnd(64, '1'),
    modules: { bind: true, kea4: true, kea6: true, d2: true },
    enrolled_at: ago(86400 * 40),
    enrolled_by: name === 'ns1' ? null : 'admin',
  }
}

function makeNodes() {
  return [
    {
      peer: peer('ns1', NODE_IDS.ns1),
      is_self: true,
      status: 'online',
      version: '0.1.0',
      config_version: 42,
      audit_count: 318,
      last_seen: ago(2),
      error: null,
    },
    {
      peer: peer('ns2', NODE_IDS.ns2),
      is_self: false,
      status: 'online',
      version: '0.1.0',
      config_version: 42,
      audit_count: 318,
      last_seen: ago(4),
      error: null,
    },
  ]
}

const BUILTIN_ROLES = [
  {
    name: 'viewer',
    builtin: true,
    description: 'Read-only access',
    permissions: ['read:dns', 'read:dhcp', 'read:hosts', 'read:alerts', 'read:series', 'read:audit', 'read:nodes'],
  },
  {
    name: 'dns-operator',
    builtin: true,
    description: 'Manage DNS zones, records and configuration',
    permissions: [
      'read:dns', 'read:dhcp', 'read:hosts', 'read:alerts', 'read:series', 'read:audit', 'read:nodes',
      'write:dns.records', 'write:dns.zones', 'write:dns.config', 'ops:dns', 'read:dns.secrets', 'write:alerts', 'read:advanced',
    ],
  },
  {
    name: 'dhcp-operator',
    builtin: true,
    description: 'Manage DHCP subnets, reservations and leases',
    permissions: [
      'read:dns', 'read:dhcp', 'read:hosts', 'read:alerts', 'read:series', 'read:audit', 'read:nodes',
      'write:dhcp.subnets', 'write:dhcp.reservations', 'write:dhcp.classes', 'write:dhcp.options', 'write:dhcp.config',
      'ops:dhcp.leases', 'read:dhcp.secrets', 'write:alerts', 'read:advanced',
    ],
  },
  { name: 'admin', builtin: true, description: 'Everything', permissions: ['*'] },
]

export const ALL_PERMISSIONS = [
  'read:dns', 'write:dns.records', 'write:dns.zones', 'write:dns.config', 'ops:dns', 'read:dns.secrets',
  'read:dhcp', 'write:dhcp.subnets', 'write:dhcp.reservations', 'write:dhcp.classes', 'write:dhcp.options',
  'write:dhcp.config', 'ops:dhcp.leases', 'ops:dhcp.ha', 'read:dhcp.secrets',
  'read:hosts', 'write:hosts', 'read:alerts', 'write:alerts', 'read:series', 'read:audit', 'read:nodes', 'read:advanced',
  'admin:nodes', 'admin:users', 'admin:roles', 'admin:settings', 'admin:install', 'admin:modules',
]

function makeUsers() {
  const base = (id, username, roles, extra = {}) => ({
    id,
    username,
    roles,
    enabled: true,
    has_totp: false,
    must_change_password: false,
    created_at: ago(86400 * 40),
    updated_at: ago(86400 * 3),
    last_login: ago(3600),
    preferences: {},
    ...extra,
  })
  return [
    { ...base('01JB00000000000000USERADMN', 'admin', ['admin']), password: 'admin' },
    { ...base('01JB00000000000000USERALCE', 'alice', ['dns-operator']), password: 'alice' },
    { ...base('01JB00000000000000USERBOBB', 'bob', ['dhcp-operator'], { has_totp: true }), password: 'bob', totp: '123456' },
    { ...base('01JB00000000000000USERVIEW', 'viewer', ['viewer'], { last_login: null }), password: 'viewer' },
  ]
}

// ---------------------------------------------------------------- DNS

function makeZones() {
  const common = {
    view: '_default',
    rclass: 'IN',
    primaries: [],
    also_notify: [],
    allow_update: [],
    forwarders: [],
    forward: null,
    dnssec_policy: null,
    inline_signing: null,
    notes: null,
    extra: {},
  }
  return [
    {
      ...common,
      name: 'example.lan.',
      kind: 'primary',
      file: 'db.example.lan',
      dynamic: true,
      allow_transfer: ['key ddi-read', '192.0.2.53'],
      update_policy: ['grant ddi-admin zonesub ANY'],
      source: 'user_conf',
      config_path: '/etc/bind/named.conf.local',
      notes: 'Main internal zone',
    },
    {
      ...common,
      name: '2.0.192.in-addr.arpa.',
      kind: 'primary',
      file: 'db.192.0.2',
      dynamic: true,
      allow_transfer: ['key ddi-read'],
      update_policy: ['grant ddi-admin zonesub ANY'],
      source: 'user_conf',
      config_path: '/etc/bind/named.conf.local',
    },
    {
      ...common,
      name: '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.',
      kind: 'primary',
      file: 'db.2001-db8',
      dynamic: true,
      allow_transfer: ['key ddi-read'],
      update_policy: ['grant ddi-admin zonesub ANY'],
      source: 'pelagos',
      config_path: '/etc/bind/pelagos/zones.conf',
    },
    {
      ...common,
      name: 'lab.example.lan.',
      kind: 'primary',
      file: 'db.lab.example.lan',
      dynamic: false,
      allow_transfer: ['none'],
      update_policy: [],
      dnssec_policy: 'default',
      inline_signing: true,
      source: 'pelagos',
      config_path: '/etc/bind/pelagos/zones.conf',
    },
    {
      ...common,
      name: 'partner.example.',
      kind: 'secondary',
      file: 'sec/db.partner.example',
      dynamic: false,
      primaries: ['192.0.2.200 key ddi-read'],
      allow_transfer: ['none'],
      update_policy: [],
      source: 'user_conf',
      config_path: '/etc/bind/named.conf.local',
    },
    {
      ...common,
      name: 'rpz.example.lan.',
      kind: 'primary',
      file: 'db.rpz',
      dynamic: false,
      allow_transfer: ['none'],
      update_policy: [],
      source: 'user_conf',
      config_path: '/etc/bind/named.conf.local',
      notes: 'Response policy zone',
    },
    {
      ...common,
      name: 'upstream.example.',
      kind: 'forward',
      file: null,
      dynamic: false,
      allow_transfer: [],
      update_policy: [],
      forwarders: ['192.0.2.1', '192.0.2.2'],
      forward: 'only',
      source: 'user_conf',
      config_path: '/etc/bind/named.conf.local',
    },
  ]
}

function rr(name, rtype, ttl, rdata) {
  return { name, rtype, ttl, rdata: Array.isArray(rdata) ? rdata : [rdata] }
}

function makeRecords(hosts) {
  const z = 'example.lan.'
  const forward = [
    rr(z, 'SOA', 3600, `ns1.${z} hostmaster.${z} 2026102401 3600 900 1209600 300`),
    rr(z, 'NS', 3600, [`ns1.${z}`, `ns2.${z}`]),
    rr(z, 'MX', 3600, `10 mail.${z}`),
    rr(z, 'TXT', 3600, '"v=spf1 mx -all"'),
    rr(`ns1.${z}`, 'A', 3600, '192.0.2.53'),
    rr(`ns1.${z}`, 'AAAA', 3600, '2001:db8::53'),
    rr(`ns2.${z}`, 'A', 3600, '192.0.2.54'),
    rr(`ns2.${z}`, 'AAAA', 3600, '2001:db8::54'),
    rr(`mail.${z}`, 'A', 3600, '192.0.2.25'),
    rr(`www.${z}`, 'CNAME', 3600, `web.${z}`),
    rr(`web.${z}`, 'A', 300, ['192.0.2.80', '192.0.2.81']),
    rr(`_ldap._tcp.${z}`, 'SRV', 3600, `0 100 389 dc.${z}`),
    rr(`dc.${z}`, 'A', 3600, '192.0.2.10'),
    rr(`printer.${z}`, 'A', 3600, '192.0.2.42'),
    rr(`v6host1.${z}`, 'AAAA', 1200, '2001:db8::1000'),
    rr(`v6host2.${z}`, 'AAAA', 1200, '2001:db8::1001'),
    rr(`router6.${z}`, 'AAAA', 3600, '2001:db8::100'),
  ]
  const reverse = [
    rr('2.0.192.in-addr.arpa.', 'SOA', 3600, `ns1.${z} hostmaster.${z} 2026102401 3600 900 1209600 300`),
    rr('2.0.192.in-addr.arpa.', 'NS', 3600, [`ns1.${z}`, `ns2.${z}`]),
    rr('53.2.0.192.in-addr.arpa.', 'PTR', 3600, `ns1.${z}`),
    rr('54.2.0.192.in-addr.arpa.', 'PTR', 3600, `ns2.${z}`),
    rr('25.2.0.192.in-addr.arpa.', 'PTR', 3600, `mail.${z}`),
    rr('10.2.0.192.in-addr.arpa.', 'PTR', 3600, `dc.${z}`),
  ]
  for (const h of hosts) {
    if (!h.forward) continue
    forward.push(rr(`${h.name}.${z}`, 'A', 1200, h.ip))
    if (h.ptr !== false) {
      const last = h.ip.split('.')[3]
      reverse.push(rr(`${last}.2.0.192.in-addr.arpa.`, 'PTR', 1200, h.ptr || `${h.name}.${z}`))
    }
  }
  const six = '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
  const lab = 'lab.example.lan.'
  const rpz = 'rpz.example.lan.'
  return {
    [z]: forward,
    '2.0.192.in-addr.arpa.': reverse,
    [six]: [
      rr(six, 'SOA', 3600, `ns1.${z} hostmaster.${z} 2026102401 3600 900 1209600 300`),
      rr(six, 'NS', 3600, [`ns1.${z}`, `ns2.${z}`]),
      rr(`3.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.${six}`, 'PTR', 3600, `ns1.${z}`),
      // DHCPv6 clients registered by DDNS: v6host1 and v6host2 (see makeLeases6).
      rr(`0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.${six}`, 'PTR', 1200, `v6host1.${z}`),
      rr(`1.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.${six}`, 'PTR', 1200, `v6host2.${z}`),
    ],
    [lab]: [
      rr(lab, 'SOA', 3600, `ns1.${z} hostmaster.${z} 2026102010 3600 900 1209600 300`),
      rr(lab, 'NS', 3600, `ns1.${z}`),
      rr(lab, 'DNSKEY', 3600, ['257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+ KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==']),
      rr(`build.${lab}`, 'A', 300, '192.0.2.150'),
    ],
    'partner.example.': [
      rr('partner.example.', 'SOA', 3600, 'ns.partner.example. admin.partner.example. 2026101503 7200 900 1209600 300'),
      rr('partner.example.', 'NS', 3600, 'ns.partner.example.'),
      rr('api.partner.example.', 'A', 3600, '192.0.2.201'),
    ],
    [rpz]: [
      rr(rpz, 'SOA', 300, `ns1.${z} hostmaster.${z} 2026102205 300 60 86400 60`),
      rr(rpz, 'NS', 300, `ns1.${z}`),
      rr(`ads.example.${rpz}`, 'CNAME', 300, '.'),
      rr(`*.ads.example.${rpz}`, 'CNAME', 300, '.'),
      rr(`malware.example.${rpz}`, 'CNAME', 300, 'rpz-drop.'),
    ],
    'upstream.example.': [],
  }
}

function soaSerial(records) {
  const soa = (records || []).find((r) => r.rtype === 'SOA')
  return soa ? Number(soa.rdata[0].split(/\s+/)[2]) : null
}

// ---------------------------------------------------------------- DHCP

function opt(name, code, data, space = 'dhcp4') {
  return { name, code, space, data, csv_format: true, always_send: null, never_send: null, raw: {} }
}

function makeSubnets4() {
  const lifetime = { valid_lifetime: 3600, min_valid_lifetime: 1800, max_valid_lifetime: 7200, preferred_lifetime: null }
  const flags = { reservations_global: false, reservations_in_subnet: true, reservations_out_of_pool: false }
  return [
    {
      id: 1,
      subnet: '192.0.2.0/25',
      family: 'v4',
      shared_network: null,
      pools: [{ pool: '192.0.2.100 - 192.0.2.126', client_classes: [], options: [], user_context: {}, raw: {} }],
      pd_pools: [],
      options: [opt('routers', 3, '192.0.2.1'), opt('domain-name-servers', 6, '192.0.2.53, 192.0.2.54'), opt('domain-name', 15, 'example.lan')],
      reservations: [],
      client_classes: [],
      relay: [],
      interface: 'eth1',
      ...lifetime,
      ...flags,
      ddns: { 'ddns-send-updates': true, 'ddns-qualifying-suffix': 'example.lan.' },
      user_context: { site: 'office', pelagos: { notes: 'Office LAN', tags: ['lan'] } },
      raw: {},
    },
    {
      id: 2,
      subnet: '192.0.2.128/26',
      family: 'v4',
      shared_network: 'campus',
      pools: [
        { pool: '192.0.2.140 - 192.0.2.159', client_classes: [], options: [], user_context: {}, raw: {} },
        { pool: '192.0.2.160 - 192.0.2.169', client_classes: ['voip'], options: [opt('tftp-server-name', 66, 'tftp.example.lan')], user_context: {}, raw: {} },
      ],
      pd_pools: [],
      options: [opt('routers', 3, '192.0.2.129')],
      reservations: [],
      client_classes: [],
      relay: ['192.0.2.129'],
      interface: null,
      ...lifetime,
      ...flags,
      ddns: {},
      user_context: {},
      raw: {},
    },
    {
      id: 3,
      subnet: '192.0.2.192/27',
      family: 'v4',
      shared_network: 'campus',
      pools: [{ pool: '192.0.2.200 - 192.0.2.219', client_classes: [], options: [], user_context: {}, raw: {} }],
      pd_pools: [],
      options: [opt('routers', 3, '192.0.2.193')],
      reservations: [],
      client_classes: ['guests'],
      relay: ['192.0.2.193'],
      interface: null,
      valid_lifetime: 900,
      min_valid_lifetime: null,
      max_valid_lifetime: null,
      preferred_lifetime: null,
      ...flags,
      ddns: { 'ddns-send-updates': false },
      user_context: { site: 'guest wifi' },
      raw: {},
    },
  ]
}

function makeSubnets6() {
  return [
    {
      id: 1,
      subnet: '2001:db8::/64',
      family: 'v6',
      shared_network: null,
      pools: [{ pool: '2001:db8::1000 - 2001:db8::1fff', client_classes: [], options: [], user_context: {}, raw: {} }],
      pd_pools: [
        {
          prefix: '2001:db8:8000::',
          prefix_len: 48,
          delegated_len: 56,
          excluded_prefix: null,
          excluded_prefix_len: null,
          client_classes: [],
          options: [],
          user_context: {},
          raw: {},
        },
      ],
      options: [opt('dns-servers', 23, '2001:db8::53, 2001:db8::54', 'dhcp6'), opt('domain-search', 24, 'example.lan', 'dhcp6')],
      reservations: [],
      client_classes: [],
      relay: [],
      interface: 'eth1',
      valid_lifetime: 7200,
      min_valid_lifetime: null,
      max_valid_lifetime: null,
      preferred_lifetime: 3600,
      reservations_global: false,
      reservations_in_subnet: true,
      reservations_out_of_pool: false,
      ddns: { 'ddns-send-updates': true },
      user_context: {},
      raw: {},
    },
  ]
}

const MAC = (n) => `02:00:5e:00:${String(Math.floor(n / 256).toString(16)).padStart(2, '0')}:${(n % 256).toString(16).padStart(2, '0')}`

// Hosts drive the leases, reservations and records so that the join is coherent,
// with a few deliberate inconsistencies for the alerts and the hosts screen.
function makeHostSeeds() {
  const seeds = []
  for (let i = 0; i < 24; i += 1) {
    const ip = `192.0.2.${100 + i}`
    seeds.push({ name: `pc${i + 1}`, ip, mac: MAC(i + 1), subnet_id: 1, forward: true, lease: true, reservation: i < 4 })
  }
  for (let i = 0; i < 18; i += 1) {
    seeds.push({ name: `lab${i + 1}`, ip: `192.0.2.${140 + i}`, mac: MAC(100 + i), subnet_id: 2, forward: i % 5 !== 0, lease: true, reservation: false })
  }
  for (let i = 0; i < 6; i += 1) {
    seeds.push({ name: `phone${i + 1}`, ip: `192.0.2.${160 + i}`, mac: MAC(200 + i), subnet_id: 2, forward: true, lease: true, reservation: true })
  }
  for (let i = 0; i < 19; i += 1) {
    seeds.push({ name: `guest${i + 1}`, ip: `192.0.2.${200 + i}`, mac: MAC(300 + i), subnet_id: 3, forward: false, lease: true, reservation: false })
  }
  // Record without lease, PTR mismatch, reservation without lease.
  seeds.push({ name: 'old-nas', ip: '192.0.2.120', mac: null, subnet_id: 1, forward: true, lease: false, reservation: false, ptr: false })
  seeds.find((s) => s.name === 'pc7').ptr = 'workstation7.example.lan.'
  seeds.push({ name: 'kiosk', ip: '192.0.2.125', mac: MAC(400), subnet_id: 1, forward: true, lease: false, reservation: true })
  return seeds.filter((s, i, all) => all.findIndex((o) => o.ip === s.ip) === i)
}

function makeLeases4(seeds) {
  const leases = []
  seeds.filter((s) => s.lease).forEach((s, i) => {
    const cltt = NOW - (i % 30) * 60000
    const valid = s.subnet_id === 3 ? 900 : 3600
    const state = i === 5 ? 'declined' : 'default'
    for (const nodeId of [NODE_IDS.ns1, NODE_IDS.ns2]) {
      leases.push({
        ip_address: s.ip,
        subnet_id: s.subnet_id,
        family: 'v4',
        hw_address: s.mac,
        client_id: `01:${s.mac}`,
        duid: null,
        hostname: s.forward || s.subnet_id !== 3 ? `${s.name}.example.lan` : s.name,
        state,
        valid_lft: valid,
        // ns2 lags a few seconds behind, as a hot-standby partner does.
        cltt: iso(nodeId === NODE_IDS.ns1 ? cltt : cltt - 3000),
        expires_at: iso(cltt + valid * 1000),
        fqdn_fwd: s.forward,
        fqdn_rev: s.forward,
        iaid: null,
        lease_type: null,
        prefix_len: null,
        preferred_lft: null,
        pool_id: s.ip.endsWith('.16') ? 1 : 0,
        user_context: {},
        node_id: nodeId,
        raw: {},
      })
    }
  })
  // One lease the standby does not know: HA disagreement for the lease detail.
  const lone = leases.find((l) => l.ip_address === '192.0.2.157' && l.node_id === NODE_IDS.ns2)
  if (lone) leases.splice(leases.indexOf(lone), 1)
  return leases
}

function makeLeases6() {
  const leases = []
  for (let i = 0; i < 12; i += 1) {
    const ip = `2001:db8::${(0x1000 + i).toString(16)}`
    const cltt = NOW - i * 120000
    leases.push({
      ip_address: ip,
      subnet_id: 1,
      family: 'v6',
      hw_address: MAC(500 + i),
      client_id: null,
      duid: `00:03:00:01:${MAC(500 + i)}`,
      hostname: `v6host${i + 1}.example.lan`,
      state: 'default',
      valid_lft: 7200,
      cltt: iso(cltt),
      expires_at: iso(cltt + 7200000),
      fqdn_fwd: true,
      fqdn_rev: true,
      iaid: 1000 + i,
      lease_type: 'IA_NA',
      prefix_len: 128,
      preferred_lft: 3600,
      pool_id: 0,
      user_context: {},
      node_id: NODE_IDS.ns1,
      raw: {},
    })
  }
  leases.push({
    ip_address: '2001:db8:8000:100::',
    subnet_id: 1,
    family: 'v6',
    hw_address: MAC(600),
    client_id: null,
    duid: `00:03:00:01:${MAC(600)}`,
    hostname: null,
    state: 'default',
    valid_lft: 7200,
    cltt: ago(600),
    expires_at: iso(NOW + 6600000),
    fqdn_fwd: false,
    fqdn_rev: false,
    iaid: 1,
    lease_type: 'IA_PD',
    prefix_len: 56,
    preferred_lft: 3600,
    pool_id: 0,
    user_context: {},
    node_id: NODE_IDS.ns1,
    raw: {},
  })
  return leases
}

function makeReservations4(seeds) {
  return seeds
    .filter((s) => s.reservation)
    .map((s) => ({
      subnet_id: s.subnet_id,
      id_type: 'hw-address',
      identifier: s.mac,
      ip_address: s.ip,
      ip_addresses: [],
      prefixes: [],
      hostname: `${s.name}.example.lan`,
      client_classes: s.name.startsWith('phone') ? ['voip'] : [],
      options: [],
      next_server: null,
      server_hostname: null,
      boot_file_name: null,
      user_context: { pelagos: { owner: s.name.startsWith('phone') ? 'telecom' : 'it', notes: `Reserved for ${s.name}` } },
      raw: {},
    }))
}

function makeReservations6() {
  return [
    {
      subnet_id: 1,
      id_type: 'duid',
      identifier: '00:03:00:01:02:00:5e:00:07:00',
      ip_address: null,
      ip_addresses: ['2001:db8::100'],
      prefixes: ['2001:db8:8000:200::/56'],
      hostname: 'router6.example.lan',
      client_classes: [],
      options: [],
      next_server: null,
      server_hostname: null,
      boot_file_name: null,
      user_context: {},
      raw: {},
    },
  ]
}

function makeClasses(family) {
  const space = family === 'v4' ? 'dhcp4' : 'dhcp6'
  return [
    {
      name: 'voip',
      test: "substring(option[60].hex,0,6) == 'Polycom'",
      options: family === 'v4' ? [opt('tftp-server-name', 66, 'tftp.example.lan')] : [],
      option_def: [],
      only_in_additional_list: false,
      next_server: null,
      server_hostname: null,
      boot_file_name: null,
      user_context: {},
      raw: {},
    },
    {
      name: 'guests',
      test: "relay4[1].hex == 'guest-wifi'",
      options: [opt(family === 'v4' ? 'domain-name-servers' : 'dns-servers', family === 'v4' ? 6 : 23, family === 'v4' ? '192.0.2.53' : '2001:db8::53', space)],
      option_def: [],
      only_in_additional_list: null,
      next_server: null,
      server_hostname: null,
      boot_file_name: null,
      user_context: { pelagos: { notes: 'Guest network' } },
      raw: {},
    },
    {
      name: 'pxe-uefi',
      test: 'option[93].hex == 0x0007',
      options: [],
      option_def: [],
      only_in_additional_list: true,
      next_server: '192.0.2.10',
      server_hostname: null,
      boot_file_name: 'ipxe.efi',
      user_context: {},
      raw: {},
    },
  ]
}

function haState(nodeId, family, selfName, partnerState, state, role) {
  return {
    node_id: nodeId,
    family,
    collected_at: ago(5),
    server_name: selfName,
    mode: 'hot-standby',
    role,
    state,
    scopes: role === 'primary' ? [selfName] : [],
    unsent_update_count: 0,
    partner: {
      role: role === 'primary' ? 'standby' : 'primary',
      state: partnerState,
      scopes: role === 'primary' ? [] : [selfName === 'ns1' ? 'ns2' : 'ns1'],
      in_touch: true,
      last_state: partnerState,
      age: 3,
      connecting_clients: 0,
      unacked_clients: 0,
      unacked_clients_left: 0,
      analyzed_packets: 0,
    },
    enabled: true,
    raw: {},
  }
}

function makeHa(family) {
  return [
    haState(NODE_IDS.ns1, family, 'ns1', 'hot-standby', 'hot-standby', 'primary'),
    haState(NODE_IDS.ns2, family, 'ns2', 'hot-standby', 'hot-standby', 'standby'),
  ]
}

function d2Stats(nodeId, errors) {
  return {
    node_id: nodeId,
    collected_at: ago(10),
    totals: {
      'ncr-received': 1420,
      'ncr-invalid': 0,
      'ncr-error': errors,
      'update-sent': 2840,
      'update-signed': 2840,
      'update-unsigned': 0,
      'update-success': 2840 - errors,
      'update-timeout': Math.floor(errors / 2),
      'update-error': errors - Math.floor(errors / 2),
    },
    per_key: {
      'ddi-admin.': { 'update-sent': 2840, 'update-success': 2840 - errors, 'update-timeout': Math.floor(errors / 2), 'update-error': errors - Math.floor(errors / 2) },
    },
    raw: {},
  }
}

function dnsCapabilities() {
  return {
    engine: 'bind',
    version: '9.20.11',
    running: true,
    rndc: true,
    statistics_channel: true,
    views: ['_default'],
    tsig_read_key: 'ddi-read',
    tsig_admin_key: 'ddi-admin',
    dnssec: true,
    catalog_zones: true,
  }
}

function dhcpCapabilities(engine) {
  return {
    engine,
    version: '3.2.1',
    running: true,
    control_socket: engine === 'kea4' ? '/run/kea/kea4-ctrl-socket' : '/run/kea/kea6-ctrl-socket',
    hooks: ['lease_cmds', 'host_cmds', 'subnet_cmds', 'stat_cmds', 'ha'],
    lease_cmds: true,
    host_cmds: true,
    subnet_cmds: true,
    stat_cmds: true,
    ha: true,
    degraded: false,
    config_write: true,
    lease_backend: 'memfile',
    multi_threading: true,
  }
}

function makeAlerts() {
  const a = (id, kind, severity, state, subject, title, extra = {}) => ({
    id,
    kind,
    severity,
    state,
    node_id: null,
    engine: null,
    subject,
    title,
    details: {},
    first_seen: ago(7200),
    last_seen: ago(60),
    acked_by: null,
    acked_at: null,
    resolved_at: null,
    ...extra,
  })
  return [
    a('ALRT0000000000000000000001', 'pool_near_full', 'warning', 'open', 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', 'Pool 192.0.2.200 - 192.0.2.219 is 95% full', {
      engine: 'kea4',
      node_id: NODE_IDS.ns1,
      details: { subnet_id: 3, assigned: 19, total: 20, percent: 95 },
    }),
    a('ALRT0000000000000000000002', 'record_without_lease', 'info', 'open', 'ip:192.0.2.120', 'old-nas.example.lan. has an A record but no lease', {
      details: { name: 'old-nas.example.lan.', ip: '192.0.2.120' },
    }),
    a('ALRT0000000000000000000003', 'ptr_mismatch', 'warning', 'open', 'ip:192.0.2.106', 'PTR for 192.0.2.106 points to workstation7.example.lan.', {
      details: { ip: '192.0.2.106', ptr: 'workstation7.example.lan.', expected: 'pc7.example.lan.' },
    }),
    a('ALRT0000000000000000000004', 'lease_without_record', 'info', 'open', 'ip:192.0.2.140', 'Lease 192.0.2.140 (lab1) has no DNS record', {
      details: { ip: '192.0.2.140', hostname: 'lab1.example.lan' },
    }),
    a('ALRT0000000000000000000005', 'insecure_key', 'critical', 'open', 'key:rndc-key', 'rndc key uses hmac-md5', {
      engine: 'bind',
      node_id: NODE_IDS.ns2,
      details: { algorithm: 'hmac-md5' },
    }),
    a('ALRT0000000000000000000006', 'd2_errors', 'warning', 'acked', 'd2:ns2', '4 DNS update errors on ns2', {
      engine: 'd2',
      node_id: NODE_IDS.ns2,
      acked_by: 'alice',
      acked_at: ago(1800),
      details: { 'update-error': 2, 'update-timeout': 2 },
    }),
    a('ALRT0000000000000000000007', 'ha_transition', 'info', 'resolved', 'kea4:ha:ns2', 'ns2 went from syncing to hot-standby', {
      engine: 'kea4',
      node_id: NODE_IDS.ns2,
      resolved_at: ago(3500),
    }),
    a('ALRT0000000000000000000008', 'reservation_mismatch', 'warning', 'open', 'ip:192.0.2.125', 'Reservation for kiosk has no lease and the host is unreachable', {
      details: { ip: '192.0.2.125', mac: MAC(400) },
    }),
    a('ALRT0000000000000000000009', 'config_divergence', 'warning', 'open', 'd2:config-file', '/etc/kea/kea-dhcp-ddns.conf differs from the running d2 configuration', {
      title_message: { key: 'alert.config_file_divergence', params: { path: '/etc/kea/kea-dhcp-ddns.conf', engine: 'd2' } },
      engine: 'd2',
      node_id: NODE_IDS.ns1,
      details: { path: '/etc/kea/kea-dhcp-ddns.conf', differences: ["/tsig-keys[0]/algorithm: 'HMAC-SHA256' in the file, 'HMAC-MD5' running"], count: 1, cause: 'file' },
    }),
  ]
}

function makeAudit() {
  const entries = []
  const actions = [
    ['dns.rrset.apply', 'zone:example.lan./printer/A', 'bind', 'alice', 'ok', '--- a/example.lan.\n+++ b/example.lan.\n@@ -1 +1 @@\n-printer.example.lan. 3600 IN A 192.0.2.41\n+printer.example.lan. 3600 IN A 192.0.2.42\n'],
    ['dhcp.reservation.apply', 'kea4:subnet:1:reservation:hw-address=02:00:5e:00:00:01', 'kea4', 'bob', 'ok', null],
    ['auth.login', 'user:alice', null, 'alice', 'ok', null],
    ['auth.login', 'user:mallory', null, null, 'denied', null],
    ['dns.key.reveal', 'key:ddi-admin', 'bind', 'admin', 'ok', null],
    ['alert.ack', 'alert:ALRT0000000000000000000006', null, 'alice', 'ok', null],
    ['dhcp.subnet.apply', 'kea4:subnet:3', 'kea4', 'bob', 'rolled_back', '--- a/kea-dhcp4.conf\n+++ b/kea-dhcp4.conf\n@@ -12,3 +12,3 @@\n-      "valid-lifetime": 1800,\n+      "valid-lifetime": 900,\n'],
    ['node.enroll', 'node:ns2', null, 'admin', 'ok', null],
    ['dns.config.apply', 'options/forwarders', 'bind', 'admin', 'error', null],
  ]
  for (let i = 0; i < 60; i += 1) {
    const [action, target, engine, user, result, diff] = actions[i % actions.length]
    const ts = NOW - i * 1800 * 1000
    entries.push({
      id: ulid(ts),
      ts: iso(ts),
      node_id: i % 3 === 0 ? NODE_IDS.ns2 : NODE_IDS.ns1,
      user,
      action,
      target,
      engine,
      plan_id: action.endsWith('.apply') ? ulid(ts - 1000) : null,
      request: action.startsWith('dns.rrset') ? { update: 'update delete printer.example.lan. A\nupdate add printer.example.lan. 3600 A 192.0.2.42' } : {},
      response: result === 'error' ? { tool: 'named-checkconf', output: "named.conf:14: unknown option 'forwarder'" } : { rcode: 'NOERROR' },
      diff,
      result,
      message: result === 'denied' ? 'invalid credentials' : null,
      client_ip: '192.0.2.99',
    })
  }
  return entries
}

function makeSettings() {
  return {
    require_totp: false,
    session_idle_seconds: 1800,
    session_ttl_seconds: 43200,
    login_rate_limit_per_minute: 10,
    plan_ttl_seconds: 600,
    // cluster.toml [settings] as GET /admin/settings returns it (architecture section 10).
    alerts_pool_warning_percent: 80,
    alerts_pool_critical_percent: 95,
    alerts_serial_divergence_seconds: 900,
    alerts_d2_error_rate: 0.05,
    dns: {
      read_key: 'ddi-read',
      admin_key: 'ddi-admin',
      update_types_admin: ['A', 'AAAA', 'PTR', 'CNAME', 'TXT', 'SRV', 'MX', 'DHCID'],
      update_types_kea: ['A', 'AAAA', 'PTR', 'DHCID'],
    },
    kea: { ddns_key: 'kea-ddns' },
    collector: { poll_seconds: 60, pool_sample_seconds: 300, peer_poll_seconds: 30, consistency_seconds: 900 },
    retention: { pool_raw_days: 7, pool_hourly_days: 365, serial_days: 90, ha_transition_days: 365, alerts_resolved_days: 90, backups_days: 90 },
  }
}

function makeHistory() {
  const items = []
  for (let i = 0; i < 12; i += 1) {
    const ts = NOW - i * 5400 * 1000
    const engine = i % 2 === 0 ? 'bind' : 'kea4'
    items.push({
      id: ulid(ts),
      engine,
      node_id: i % 3 === 0 ? NODE_IDS.ns2 : NODE_IDS.ns1,
      ts: iso(ts),
      plan_id: ulid(ts - 500),
      label: engine === 'bind' ? 'zones.conf: add lab.example.lan.' : 'kea-dhcp4.conf: subnet 3 lifetime',
      files: engine === 'bind' ? ['/etc/bind/pelagos/zones.conf'] : ['/etc/kea/kea-dhcp4.conf'],
    })
  }
  return items
}

// Backed-up file contents per history id, different for each backup so that
// consecutive backups of the same file show a diff.
function makeHistoryFiles(history) {
  const files = {}
  history.forEach((item, i) => {
    const step = 12 - i
    files[item.id] = item.engine === 'bind'
      ? { [item.files[0]]: `// pelagos:managed\n${Array.from({ length: Math.ceil(step / 2) }, (_, z) => `zone "lab${z}.example.lan" {\n\ttype primary;\n\tfile "db.lab${z}.example.lan";\n};`).join('\n')}\n` }
      : { [item.files[0]]: `${JSON.stringify({ Dhcp4: { 'valid-lifetime': 3600, 'subnet4': [{ id: 3, subnet: '192.0.2.128/26', 'valid-lifetime': 600 + step * 100 }] } }, null, 2)}\n` }
  })
  return files
}

export function createState() {
  const seeds = makeHostSeeds()
  const zones = makeZones()
  const records = makeRecords(seeds)
  const subnets4 = makeSubnets4()
  const reservations4 = makeReservations4(seeds)
  const history = makeHistory()
  return {
    selfId: SELF_ID,
    nodeIds: NODE_IDS,
    nodes: makeNodes(),
    users: makeUsers(),
    customRoles: [{ name: 'helpdesk', builtin: false, description: 'Read and reservations', permissions: ['read:dns', 'read:dhcp', 'read:hosts', 'write:dhcp.reservations'] }],
    builtinRoles: BUILTIN_ROLES,
    sessions: new Map(),
    zones,
    records,
    soaSerial,
    catalogs: [
      { zone: 'catalog.example.lan.', view: '_default', role: 'producer', version: '2', source: 'pelagos', members: [{ zone: 'lab.example.lan.', label: 'a1b2c3', group: 'lab', coo: null }] },
      { zone: 'catalog.partner.example.', view: '_default', role: 'consumer', version: '2', statement: '{ zone "catalog.partner.example" default-primaries { 192.0.2.200 key ddi-read; }; }', default_primaries: ['192.0.2.200 key ddi-read'], options: {}, members: [{ zone: 'partner.example.', label: 'd4e5f6', group: null, coo: null }] },
    ],
    dnssecPolicies: [
      { name: 'fast', statements: [{ name: 'keys', value: '{ csk lifetime unlimited algorithm ecdsap256sha256; }' }, { name: 'signatures-validity', value: '14d' }], source: 'pelagos', config_path: '/etc/bind/pelagos/policies.conf', line: 2 },
    ],
    dnsCapabilities: dnsCapabilities(),
    dhcpCapabilities: { v4: dhcpCapabilities('kea4'), v6: dhcpCapabilities('kea6') },
    keys: [
      { name: 'ddi-admin', algorithm: 'hmac-sha256', source: 'pelagos', config_path: '/etc/bind/pelagos/keys.conf', used_by: ['update-policy example.lan.', 'kea-dhcp-ddns'], secret: 'c2VjcmV0LWFkbWluLWtleS1mb3ItdGhlLW1vY2s=' },
      { name: 'ddi-read', algorithm: 'hmac-sha256', source: 'pelagos', config_path: '/etc/bind/pelagos/keys.conf', used_by: ['allow-transfer example.lan.'], secret: 'c2VjcmV0LXJlYWQta2V5LWZvci10aGUtbW9jaw==' },
      { name: 'rndc-key', algorithm: 'hmac-md5', source: 'user_conf', config_path: '/etc/bind/rndc.key', used_by: ['controls'], secret: 'bGVnYWN5LXJuZGMta2V5' },
    ],
    acls: [
      { name: 'internal', elements: ['192.0.2.0/24', '2001:db8::/64', 'localhost'], source: 'pelagos', config_path: '/etc/bind/pelagos/acls.conf' },
      { name: 'secondaries', elements: ['192.0.2.54', 'key ddi-read'], source: 'pelagos', config_path: '/etc/bind/pelagos/acls.conf' },
    ],
    resolver: {
      recursion: true,
      allow_recursion: ['internal'],
      forwarders: ['192.0.2.1', '2001:db8::1'],
      forward: 'first',
      dnssec_validation: 'auto',
    },
    subnets: { v4: subnets4, v6: makeSubnets6() },
    sharedNetworks: {
      v4: [{ name: 'campus', family: 'v4', subnets: [], options: [opt('domain-name', 15, 'campus.example.lan')], interface: 'eth2', relay: [], user_context: {}, raw: {} }],
      v6: [],
    },
    classes: { v4: makeClasses('v4'), v6: makeClasses('v6') },
    globalOptions: {
      v4: [opt('domain-name-servers', 6, '192.0.2.53, 192.0.2.54'), opt('domain-name', 15, 'example.lan'), opt('ntp-servers', 42, '192.0.2.1')],
      v6: [opt('dns-servers', 23, '2001:db8::53', 'dhcp6')],
    },
    reservations: { v4: reservations4, v6: makeReservations6() },
    leases: { v4: makeLeases4(seeds), v6: makeLeases6() },
    ha: { v4: makeHa('v4'), v6: makeHa('v6') },
    serviceEnabled: { v4: { [NODE_IDS.ns1]: true, [NODE_IDS.ns2]: true }, v6: { [NODE_IDS.ns1]: true, [NODE_IDS.ns2]: true } },
    ddns: {
      v4: {
        dhcp_ddns: { 'enable-updates': true, 'server-ip': '127.0.0.1', 'server-port': 53001, 'ncr-protocol': 'UDP', 'ncr-format': 'JSON' },
        ddns_params: { 'ddns-send-updates': true, 'ddns-override-client-update': true, 'ddns-replace-client-name': 'when-not-present', 'ddns-qualifying-suffix': 'example.lan.', 'ddns-update-on-renew': false },
      },
      v6: {
        dhcp_ddns: { 'enable-updates': true, 'server-ip': '127.0.0.1', 'server-port': 53001 },
        ddns_params: { 'ddns-send-updates': true, 'ddns-qualifying-suffix': 'example.lan.' },
      },
    },
    hooks: {
      v4: [
        { library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so', parameters: {}, known: true, name: 'lease_cmds' },
        { library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_host_cmds.so', parameters: {}, known: true, name: 'host_cmds' },
        { library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_subnet_cmds.so', parameters: {}, known: true, name: 'subnet_cmds' },
        { library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_stat_cmds.so', parameters: {}, known: true, name: 'stat_cmds' },
        {
          library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so',
          parameters: { 'high-availability': [{ 'this-server-name': 'ns1', mode: 'hot-standby', peers: [{ name: 'ns1', role: 'primary' }, { name: 'ns2', role: 'standby' }] }] },
          known: true,
          name: 'ha',
        },
      ],
      v6: [
        { library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so', parameters: {}, known: true, name: 'lease_cmds' },
        { library: '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so', parameters: {}, known: true, name: 'ha' },
      ],
    },
    availableHooks: [['lease_cmds', 'Lease commands (lease4-get, lease4-del, ...)'], ['host_cmds', 'Host reservation commands'], ['subnet_cmds', 'Subnet and shared network commands'], ['stat_cmds', 'Lease statistics per subnet and pool'], ['ha', 'High availability'], ['flex_id', 'Flexible identifier'], ['class_cmds', 'Client class commands'], ['run_script', 'External script hook'], ['bootp', 'BOOTP support'], ['limits', 'Rate limits per class or subnet']].map(([name, description]) => ({ name, description })),
    d2: { [NODE_IDS.ns1]: d2Stats(NODE_IDS.ns1, 0), [NODE_IDS.ns2]: d2Stats(NODE_IDS.ns2, 4) },
    alerts: makeAlerts(),
    // Section 9: the D2 file of this node was edited by hand; the Kea files agree.
    keaFiles: {
      v4: { path: '/etc/kea/kea-dhcp4.conf', diverged: false, differences: [] },
      v6: { path: '/etc/kea/kea-dhcp6.conf', diverged: false, differences: [] },
      d2: { path: '/etc/kea/kea-dhcp-ddns.conf', diverged: true, differences: ["/tsig-keys[0]/algorithm: 'HMAC-SHA256' in the file, 'HMAC-MD5' running"] },
    },
    audit: makeAudit(),
    settings: makeSettings(),
    modules: { cluster: { dhcpv6: true, advanced_editor: true } },
    history,
    historyFiles: makeHistoryFiles(history),
    plans: new Map(),
    jobs: new Map(),
    layouts: new Map(),
    preferences: new Map(),
    enrollTokens: [],
    hostSeeds: seeds,
  }
}

export { NOW, ago, soaSerial }
