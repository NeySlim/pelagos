// SPDX-License-Identifier: Apache-2.0
// What a route answers instead of a silent redirect: unknown path, missing permission,
// disabled module. Always offers the way back to the dashboard.
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Compass, LockKey, PuzzlePiece } from '@phosphor-icons/react'
import { EmptyState } from './EmptyState'

const KINDS = {
  not_found: { icon: Compass, title: 'routeStatus.notFound', description: 'routeStatus.notFoundHelp' },
  forbidden: { icon: LockKey, title: 'routeStatus.forbidden', description: 'routeStatus.forbiddenHelp' },
  module_disabled: { icon: PuzzlePiece, title: 'routeStatus.moduleDisabled', description: 'routeStatus.moduleDisabledHelp' },
}

export function RouteStatus({ kind = 'not_found' }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const spec = KINDS[kind] || KINDS.not_found
  return (
    <div className="flex items-center justify-center h-full min-h-[300px]" data-testid={`route-${kind}`} role="alert">
      <EmptyState
        icon={spec.icon}
        title={t(spec.title)}
        description={t(spec.description)}
        action={{ label: t('routeStatus.backToDashboard'), onClick: () => navigate('/') }}
      />
    </div>
  )
}

export default RouteStatus
