// SPDX-License-Identifier: Apache-2.0
// Install and import area: detection, install/import plan wizard, security audit.
import { lazyPage } from '../../lib/lazyPage'
import { ArrowsLeftRight, DownloadSimple, ShieldWarning } from '@phosphor-icons/react'

const InstallPage = lazyPage(() => import('./InstallPage'))
const SecurityPage = lazyPage(() => import('./SecurityPage'))
const KeaMigrationPage = lazyPage(() => import('./KeaMigrationPage'))

const perm = 'admin:install'

export default {
  id: 'install',
  routes: [
    { path: '/install', component: InstallPage, permission: perm },
    { path: '/install/security', component: SecurityPage, permission: perm },
    { path: '/install/kea-migration', component: KeaMigrationPage, permission: perm },
  ],
  nav: [
    { id: 'install', group: 'admin', path: '/install', labelKey: 'install:nav.install', icon: DownloadSimple, permission: perm, order: 81 },
    { id: 'install-security', group: 'admin', path: '/install/security', labelKey: 'install:nav.security', icon: ShieldWarning, permission: perm, order: 82 },
    { id: 'install-kea-migration', group: 'admin', path: '/install/kea-migration', labelKey: 'install:nav.keaMigration', icon: ArrowsLeftRight, permission: perm, order: 83 },
  ],
}
