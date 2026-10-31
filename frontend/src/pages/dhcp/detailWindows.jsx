// SPDX-License-Identifier: Apache-2.0
// Registers the `lease` floating window at startup (imported by routes.js), so any
// page can open a lease card; the card itself loads on first use.
import { Suspense } from 'react'
import { lazyPage } from '../../lib/lazyPage'
import { Clock } from '@phosphor-icons/react'
import { registerDetailRenderer } from '../../components/FloatingDetailWindow'
import { LoadingSpinner } from '../../components/LoadingSpinner'

const LeaseWindow = lazyPage(() => import('./LeaseDetail'))

export function LazyLeaseWindow(props) {
  return (
    <Suspense fallback={<LoadingSpinner size="sm" />}>
      <LeaseWindow {...props} />
    </Suspense>
  )
}

registerDetailRenderer('lease', {
  component: LazyLeaseWindow,
  icon: Clock,
  iconClass: 'icon-bg-violet',
  meta: (data) => ({ title: data?.ip, subtitle: data?.subtitle || (data?.family === 'v6' ? 'DHCPv6' : 'DHCPv4') }),
})
