// SPDX-License-Identifier: Apache-2.0
// Administration area: users, roles, modules, settings.
import { lazy } from 'react'
import { Users, UserGear, SquaresFour, Gear } from '@phosphor-icons/react'

const UsersPage = lazy(() => import('./UsersPage'))
const RolesPage = lazy(() => import('./RolesPage'))
const ModulesPage = lazy(() => import('./ModulesPage'))
const SettingsPage = lazy(() => import('./SettingsPage'))

export default {
  id: 'admin',
  routes: [
    { path: '/admin/users', component: UsersPage, permission: 'admin:users' },
    { path: '/admin/roles', component: RolesPage, permission: 'admin:roles' },
    { path: '/admin/modules', component: ModulesPage, permission: 'admin:modules' },
    { path: '/admin/settings', component: SettingsPage, permission: 'admin:settings' },
  ],
  nav: [
    { id: 'admin-users', group: 'admin', path: '/admin/users', labelKey: 'admin:nav.users', icon: Users, permission: 'admin:users', order: 83 },
    { id: 'admin-roles', group: 'admin', path: '/admin/roles', labelKey: 'admin:nav.roles', icon: UserGear, permission: 'admin:roles', order: 84 },
    { id: 'admin-modules', group: 'admin', path: '/admin/modules', labelKey: 'admin:nav.modules', icon: SquaresFour, permission: 'admin:modules', order: 85 },
    { id: 'admin-settings', group: 'admin', path: '/admin/settings', labelKey: 'admin:nav.settings', icon: Gear, permission: 'admin:settings', order: 87 },
  ],
}
