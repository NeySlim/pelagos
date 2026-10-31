// SPDX-License-Identifier: Apache-2.0
// DNS area: zones and records, resolver, ACLs and keys, secondaries, DNSSEC, RPZ, catalog zones,
// instance statistics, orphan PTRs.
import { lazyPage } from '../../lib/lazyPage'
import { Globe, ArrowsLeftRight, Key, CopySimple, ShieldCheck, Prohibit, BookOpen, ChartBar, LinkBreak } from '@phosphor-icons/react'

const ZonesPage = lazyPage(() => import('./ZonesPage'))
const ZoneDetailPage = lazyPage(() => import('./ZoneDetailPage'))
const ResolverPage = lazyPage(() => import('./ResolverPage'))
const AclsKeysPage = lazyPage(() => import('./AclsKeysPage'))
const SecondariesPage = lazyPage(() => import('./SecondariesPage'))
const DnssecPage = lazyPage(() => import('./DnssecPage'))
const RpzPage = lazyPage(() => import('./RpzPage'))
const CatalogsPage = lazyPage(() => import('./CatalogsPage'))
const InstancesPage = lazyPage(() => import('./InstancesPage'))
const PtrOrphansPage = lazyPage(() => import('./PtrOrphansPage'))

const read = 'read:dns'

export default {
  id: 'dns',
  routes: [
    { path: '/dns/zones', component: ZonesPage, permission: read },
    { path: '/dns/zones/:zone', component: ZoneDetailPage, permission: read },
    { path: '/dns/resolver', component: ResolverPage, permission: read },
    { path: '/dns/acls-keys', component: AclsKeysPage, permission: read },
    { path: '/dns/secondaries', component: SecondariesPage, permission: read },
    { path: '/dns/dnssec', component: DnssecPage, permission: read },
    { path: '/dns/rpz', component: RpzPage, permission: read },
    { path: '/dns/catalogs', component: CatalogsPage, permission: read },
    { path: '/dns/instances', component: InstancesPage, permission: read },
    { path: '/dns/ptr-orphans', component: PtrOrphansPage, permission: read },
  ],
  nav: [
    { id: 'dns-zones', group: 'dns', path: '/dns/zones', labelKey: 'dns:nav.zones', icon: Globe, permission: read, order: 10 },
    { id: 'dns-resolver', group: 'dns', path: '/dns/resolver', labelKey: 'dns:nav.resolver', icon: ArrowsLeftRight, permission: read, order: 11 },
    { id: 'dns-acls-keys', group: 'dns', path: '/dns/acls-keys', labelKey: 'dns:nav.aclsKeys', icon: Key, permission: read, order: 12 },
    { id: 'dns-secondaries', group: 'dns', path: '/dns/secondaries', labelKey: 'dns:nav.secondaries', icon: CopySimple, permission: read, order: 13 },
    { id: 'dns-dnssec', group: 'dns', path: '/dns/dnssec', labelKey: 'dns:nav.dnssec', icon: ShieldCheck, permission: read, order: 14 },
    { id: 'dns-rpz', group: 'dns', path: '/dns/rpz', labelKey: 'dns:nav.rpz', icon: Prohibit, permission: read, order: 15 },
    { id: 'dns-catalogs', group: 'dns', path: '/dns/catalogs', labelKey: 'dns:nav.catalogs', icon: BookOpen, permission: read, order: 16 },
    { id: 'dns-instances', group: 'dns', path: '/dns/instances', labelKey: 'dns:nav.instances', icon: ChartBar, permission: read, order: 17 },
    { id: 'dns-ptr-orphans', group: 'dns', path: '/dns/ptr-orphans', labelKey: 'dns:nav.ptrOrphans', icon: LinkBreak, permission: read, order: 18 },
  ],
}
