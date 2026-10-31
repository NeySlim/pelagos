// SPDX-License-Identifier: Apache-2.0
// Dashboard area: react-grid-layout tiles (HA, pools, zone sync, D2 errors,
// inconsistencies, nodes). The dashboard nav entry is rendered apart by the Sidebar.
import { lazyPage } from '../../lib/lazyPage'
import { Gauge } from '@phosphor-icons/react'

const DashboardPage = lazyPage(() => import('./DashboardPage'))

export default {
  id: 'dashboard',
  routes: [{ path: '/', component: DashboardPage }],
  nav: [{ id: 'dashboard', group: null, path: '/', labelKey: 'common:nav.dashboard', icon: Gauge, order: 0 }],
}
