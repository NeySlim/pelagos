// SPDX-License-Identifier: Apache-2.0
// Application layout: desktop sidebar or mobile header with a grid menu, the routed
// page in <Outlet/>, and the floating detail windows above everything.
import { useState, useEffect, useLayoutEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet, useLocation, useNavigationType, Link, useNavigate } from 'react-router-dom'
import { List, X, House, UserCircle, SignOut } from '@phosphor-icons/react'
import { Sidebar, useVisibleNavItems } from './Sidebar'
import { WebSocketIndicator } from './WebSocketIndicator'
import { Logo } from './Logo'
import { AppBackdrop, AmbientScreen, IconButton, PageTransition } from './motion'
import { useBootSequence } from '../hooks/useBootSequence'
import { useMagnetic } from '../hooks/useMagnetic'
import { navDirection } from '../lib/viewTransition'
import { useTheme } from '../contexts/ThemeContext'
import { cn } from '../lib/utils'
import { useAuth } from '../contexts/AuthContext'
import { useMobile } from '../contexts/MobileContext'
import { navGroups, resolveActiveNavId, allNavItems } from '../pages/routes'

export function AppShell() {
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { isMobile } = useMobile()
  const { effects } = useTheme()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  useBootSequence()
  useMagnetic()
  // data-dir tells the page entry which way to move (a pop has no view transition).
  const navType = useNavigationType()
  const lastPath = useRef(location.pathname)
  useLayoutEffect(() => {
    document.documentElement.dataset.dir = navDirection(lastPath.current, location.pathname, navType)
    lastPath.current = location.pathname
  }, [location.pathname, navType])
  const visibleItems = useVisibleNavItems()
  const activeId = resolveActiveNavId(location.pathname)

  useEffect(() => {
    setMobileMenuOpen(false)
  }, [location.pathname])

  const groups = useMemo(
    () => navGroups.map((g) => ({ ...g, items: visibleItems.filter((i) => i.group === g.id) })).filter((g) => g.items.length > 0),
    [visibleItems],
  )
  const activeItem = allNavItems.find((i) => i.id === activeId)

  return (
    <div className="ui-app relative flex h-full w-full overflow-hidden bg-bg-primary">
      {effects === 'mission' && <AppBackdrop />}
      {effects === 'instrument' && <AmbientScreen />}
      <div className="relative z-[1] flex flex-col w-full h-full overflow-hidden">
        {isMobile && (
          <header className="ui-topbar shrink-0 h-10 bg-bg-secondary border-b border-border-op50 flex items-center px-2 z-40 gap-1">
            <Logo variant="icon" withText={false} size="xs" />
            <span className="ml-1 text-xs font-medium text-text-primary truncate flex-1">{activeItem ? t(activeItem.labelKey) : 'Pelagos'}</span>
            <WebSocketIndicator className="scale-90" />
            <IconButton
              icon={mobileMenuOpen ? X : List}
              label={t('nav.menu')}
              size="sm"
              active={mobileMenuOpen}
              aria-expanded={mobileMenuOpen}
              onClick={() => setMobileMenuOpen((o) => !o)}
            />
          </header>
        )}

        {isMobile && mobileMenuOpen && (
          <>
            <div className="ui-scrim fixed inset-0 bg-black/60 backdrop-blur-sm z-40" onClick={() => setMobileMenuOpen(false)} />
            <div className="fixed top-10 right-0 left-0 z-50 p-2">
              <div className="ui-menu bg-bg-secondary border border-border rounded-xl shadow-2xl p-2 max-h-[70vh] overflow-auto">
                <div className="grid grid-cols-4 gap-1 mb-1">
                  <Link to="/" className={cn('flex flex-col items-center gap-0.5 p-1.5 rounded-lg', activeId === 'dashboard' ? 'bg-accent-primary-op15 text-accent-primary' : 'text-text-secondary')}>
                    <House size={18} />
                    <span className="text-3xs font-medium">{t('nav.dashboard')}</span>
                  </Link>
                </div>
                {groups.map((group) => (
                  <div key={group.id} className="mb-1">
                    <div className="px-1 py-0.5 text-3xs font-semibold text-text-tertiary uppercase tracking-wider">{t(group.labelKey)}</div>
                    <div className="grid grid-cols-4 gap-1">
                      {group.items.map((item) => {
                        const Icon = item.icon
                        const active = activeId === item.id
                        return (
                          <Link key={item.id} to={item.path} className={cn('flex flex-col items-center gap-0.5 p-1.5 rounded-lg text-center', active ? 'bg-accent-primary-op15 text-accent-primary' : 'text-text-secondary')}>
                            {Icon && <Icon size={18} weight={active ? 'fill' : 'regular'} />}
                            <span className="text-3xs font-medium leading-tight">{t(item.labelKey)}</span>
                          </Link>
                        )
                      })}
                    </div>
                  </div>
                ))}
                <div className="mt-2 pt-2 border-t border-border flex items-center justify-between">
                  <button type="button" onClick={() => navigate('/account')} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-text-secondary hover:bg-bg-tertiary">
                    <UserCircle size={16} />
                    <span className="text-xs font-medium">{t('nav.account')}</span>
                  </button>
                  <button type="button" onClick={() => logout().then(() => navigate('/login'))} className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-status-danger hover:bg-status-danger-op10">
                    <SignOut size={16} />
                    <span className="text-xs font-medium">{t('auth.logout')}</span>
                  </button>
                </div>
              </div>
            </div>
          </>
        )}

        <div className="ui-body flex-1 flex min-h-0 overflow-hidden">
          {!isMobile && (
            <div className="ui-sidebar-slot flex-shrink-0">
              <Sidebar activeId={activeId} />
            </div>
          )}
          <main className="flex-1 flex flex-col min-h-0 min-w-0 overflow-hidden" id="main">
            {/* Keyed by nav entry, not path: a page's own sub-routes keep their state. */}
            <PageTransition routeKey={activeId || 'none'}>
              <Outlet />
            </PageTransition>
          </main>
        </div>
      </div>
    </div>
  )
}

export default AppShell
