// SPDX-License-Identifier: Apache-2.0
// DNS area: zones and records, resolver, ACLs and keys, secondaries, DNSSEC, RPZ, catalog zones.
import { lazy } from 'react'
import { Globe, ArrowsLeftRight, Key, CopySimple, ShieldCheck, Prohibit, BookOpen } from '@phosphor-icons/react'

const ZonesPage = lazy(() => import('./ZonesPage'))
const ZoneDetailPage = lazy(() => import('./ZoneDetailPage'))
const ResolverPage = lazy(() => import('./ResolverPage'))
const AclsKeysPage = lazy(() => import('./AclsKeysPage'))
const SecondariesPage = lazy(() => import('./SecondariesPage'))
const DnssecPage = lazy(() => import('./DnssecPage'))
const RpzPage = lazy(() => import('./RpzPage'))
const CatalogsPage = lazy(() => import('./CatalogsPage'))

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
  ],
  nav: [
    { id: 'dns-zones', group: 'dns', path: '/dns/zones', labelKey: 'dns:nav.zones', icon: Globe, permission: read, order: 10 },
    { id: 'dns-resolver', group: 'dns', path: '/dns/resolver', labelKey: 'dns:nav.resolver', icon: ArrowsLeftRight, permission: read, order: 11 },
    { id: 'dns-acls-keys', group: 'dns', path: '/dns/acls-keys', labelKey: 'dns:nav.aclsKeys', icon: Key, permission: read, order: 12 },
    { id: 'dns-secondaries', group: 'dns', path: '/dns/secondaries', labelKey: 'dns:nav.secondaries', icon: CopySimple, permission: read, order: 13 },
    { id: 'dns-dnssec', group: 'dns', path: '/dns/dnssec', labelKey: 'dns:nav.dnssec', icon: ShieldCheck, permission: read, order: 14 },
    { id: 'dns-rpz', group: 'dns', path: '/dns/rpz', labelKey: 'dns:nav.rpz', icon: Prohibit, permission: read, order: 15 },
    { id: 'dns-catalogs', group: 'dns', path: '/dns/catalogs', labelKey: 'dns:nav.catalogs', icon: BookOpen, permission: read, order: 16 },
  ],
}
