// SPDX-License-Identifier: Apache-2.0
// Plans area: recent plans of the node you are connected to, their rollback window, detail.
import { lazyPage } from '../../lib/lazyPage'
import { ListChecks } from '@phosphor-icons/react'

const PlansPage = lazyPage(() => import('./PlansPage'))

export default {
  id: 'plans',
  routes: [{ path: '/plans', component: PlansPage }],
  // Everyone sees their own plans; read:audit sees all of them (section 6).
  nav: [{ id: 'plans', group: 'admin', path: '/plans', labelKey: 'plans:nav.plans', icon: ListChecks, order: 87 }],
}
