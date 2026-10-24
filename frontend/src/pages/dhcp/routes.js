// SPDX-License-Identifier: Apache-2.0
// DHCP area: every screen exists once per family; pages receive `family` as a prop.
// The v6 routes and nav entries are gated by the cluster module `dhcpv6`.
import { lazy } from 'react'
import {
  Network, TreeStructure, SlidersHorizontal, Tag, Clock, BookmarkSimple, Heartbeat, ArrowsClockwise, PuzzlePiece,
} from '@phosphor-icons/react'
import './detailWindows'

const screens = [
  { id: 'subnets', path: 'subnets', icon: Network, component: lazy(() => import('./SubnetsPage')) },
  { id: 'sharedNetworks', path: 'shared-networks', icon: TreeStructure, component: lazy(() => import('./SharedNetworksPage')) },
  { id: 'options', path: 'options', icon: SlidersHorizontal, component: lazy(() => import('./OptionsPage')) },
  { id: 'classes', path: 'classes', icon: Tag, component: lazy(() => import('./ClassesPage')) },
  { id: 'leases', path: 'leases', icon: Clock, component: lazy(() => import('./LeasesPage')) },
  { id: 'reservations', path: 'reservations', icon: BookmarkSimple, component: lazy(() => import('./ReservationsPage')) },
  { id: 'ha', path: 'ha', icon: Heartbeat, component: lazy(() => import('./HaPage')) },
  { id: 'ddns', path: 'ddns', icon: ArrowsClockwise, component: lazy(() => import('./DdnsPage')) },
  { id: 'hooks', path: 'hooks', icon: PuzzlePiece, component: lazy(() => import('./HooksPage')) },
]

const families = [
  { family: 'v4', group: 'dhcp', module: undefined, order: 20 },
  { family: 'v6', group: 'dhcpv6', module: 'dhcpv6', order: 40 },
]

const read = 'read:dhcp'

export const dhcpPath = (family, screen) => `/dhcp/${family}/${screens.find((s) => s.id === screen)?.path || screen}`

export default {
  id: 'dhcp',
  routes: families.flatMap(({ family, module }) =>
    screens.map((s) => ({ path: `/dhcp/${family}/${s.path}`, component: s.component, props: { family }, permission: read, module })),
  ),
  nav: families.flatMap(({ family, group, module, order }) =>
    screens.map((s, i) => ({
      id: `dhcp-${family}-${s.id}`,
      group,
      path: `/dhcp/${family}/${s.path}`,
      labelKey: `dhcp:nav.${s.id}`,
      icon: s.icon,
      permission: read,
      module,
      order: order + i,
    })),
  ),
}
