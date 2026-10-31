// SPDX-License-Identifier: Apache-2.0
// Registers the `host` floating window at startup (imported by routes.js), so the
// dashboard, alerts or leases can open a host card; the card loads on first use.
import { Suspense } from 'react'
import { lazyPage } from '../../lib/lazyPage'
import { Desktop } from '@phosphor-icons/react'
import { registerDetailRenderer } from '../../components/FloatingDetailWindow'
import { LoadingSpinner } from '../../components/LoadingSpinner'

const HostWindow = lazyPage(() => import('./HostCard'))

export function LazyHostWindow(props) {
  return (
    <Suspense fallback={<LoadingSpinner size="sm" />}>
      <HostWindow {...props} />
    </Suspense>
  )
}

registerDetailRenderer('host', {
  component: LazyHostWindow,
  icon: Desktop,
  iconClass: 'icon-bg-violet',
  meta: (data) => ({ title: data?.title, subtitle: data?.subtitle }),
})
