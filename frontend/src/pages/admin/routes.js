// SPDX-License-Identifier: Apache-2.0
// Administration area: users, roles, modules, certificates, notifications, backups, IPv6
// sources, settings.
import { lazy } from 'react'
import { Users, UserGear, SquaresFour, Gear, Certificate, BellRinging, Archive, Globe } from '@phosphor-icons/react'

const UsersPage = lazy(() => import('./UsersPage'))
const RolesPage = lazy(() => import('./RolesPage'))
const ModulesPage = lazy(() => import('./ModulesPage'))
const SettingsPage = lazy(() => import('./SettingsPage'))
const CertificatesPage = lazy(() => import('./certs/CertificatesPage'))
const NotificationsPage = lazy(() => import('./notifications/NotificationsPage'))
const ArchivesPage = lazy(() => import('./archives/ArchivesPage'))
const Ipv6SourcesPage = lazy(() => import('./ipv6/Ipv6SourcesPage'))

export default {
  id: 'admin',
  routes: [
    { path: '/admin/users', component: UsersPage, permission: 'admin:users' },
    { path: '/admin/roles', component: RolesPage, permission: 'admin:roles' },
    { path: '/admin/modules', component: ModulesPage, permission: 'admin:modules' },
    { path: '/admin/settings', component: SettingsPage, permission: 'admin:settings' },
    { path: '/admin/certificates', component: CertificatesPage, permission: 'admin:certificates' },
    { path: '/admin/notifications', component: NotificationsPage, permission: 'admin:notifications' },
    { path: '/admin/archives', component: ArchivesPage, permission: 'admin:archives' },
    { path: '/admin/ipv6', component: Ipv6SourcesPage, permission: 'admin:settings' },
  ],
  nav: [
    { id: 'admin-users', group: 'admin', path: '/admin/users', labelKey: 'admin:nav.users', icon: Users, permission: 'admin:users', order: 83 },
    { id: 'admin-roles', group: 'admin', path: '/admin/roles', labelKey: 'admin:nav.roles', icon: UserGear, permission: 'admin:roles', order: 84 },
    { id: 'admin-modules', group: 'admin', path: '/admin/modules', labelKey: 'admin:nav.modules', icon: SquaresFour, permission: 'admin:modules', order: 85 },
    { id: 'admin-certificates', group: 'admin', path: '/admin/certificates', labelKey: 'admin:nav.certificates', icon: Certificate, permission: 'admin:certificates', order: 87 },
    { id: 'admin-notifications', group: 'admin', path: '/admin/notifications', labelKey: 'admin:nav.notifications', icon: BellRinging, permission: 'admin:notifications', order: 87.5 },
    { id: 'admin-archives', group: 'admin', path: '/admin/archives', labelKey: 'admin:nav.archives', icon: Archive, permission: 'admin:archives', order: 87.6 },
    { id: 'admin-ipv6', group: 'admin', path: '/admin/ipv6', labelKey: 'ipv6:nav.sources', icon: Globe, permission: 'admin:settings', order: 87.7 },
    { id: 'admin-settings', group: 'admin', path: '/admin/settings', labelKey: 'admin:nav.settings', icon: Gear, permission: 'admin:settings', order: 88 },
  ],
}
