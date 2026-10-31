// SPDX-License-Identifier: Apache-2.0
// Account area: password, TOTP enrollment with QR, preferences. Reached from the
// user menu (group null keeps it out of the grouped navigation).
import { lazyPage } from '../../lib/lazyPage'
import { UserCircle } from '@phosphor-icons/react'

const AccountPage = lazyPage(() => import('./AccountPage'))

export default {
  id: 'account',
  routes: [{ path: '/account', component: AccountPage }],
  nav: [{ id: 'account', group: null, path: '/account', labelKey: 'common:nav.account', icon: UserCircle, order: 99 }],
}
