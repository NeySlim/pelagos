// SPDX-License-Identifier: Apache-2.0
// Install and import area: detection, install/import plan wizard, security audit.
import { lazy } from 'react'
import { DownloadSimple, ShieldWarning } from '@phosphor-icons/react'

const InstallPage = lazy(() => import('./InstallPage'))
const SecurityPage = lazy(() => import('./SecurityPage'))

const perm = 'admin:install'

export default {
  id: 'install',
  routes: [
    { path: '/install', component: InstallPage, permission: perm },
    { path: '/install/security', component: SecurityPage, permission: perm },
  ],
  nav: [
    { id: 'install', group: 'admin', path: '/install', labelKey: 'install:nav.install', icon: DownloadSimple, permission: perm, order: 81 },
    { id: 'install-security', group: 'admin', path: '/install/security', labelKey: 'install:nav.security', icon: ShieldWarning, permission: perm, order: 82 },
  ],
}
