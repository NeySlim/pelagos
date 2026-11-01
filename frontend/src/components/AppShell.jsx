// SPDX-License-Identifier: Apache-2.0
// Application layout: desktop sidebar or mobile header with a grid menu, the routed
// page in <Outlet/>, and the floating detail windows above everything.
import { useState, useEffect, useLayoutEffect, useMemo, useRef, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet, useLocation, useNavigationType, Link, useNavigate } from 'react-router-dom'
import { List, X, House, UserCircle, SignOut, MagnifyingGlass, CaretDown } from '@phosphor-icons/react'
import { Sidebar, useVisibleNavItems } from './Sidebar'
import { WebSocketIndicator } from './WebSocketIndicator'
import { Logo } from './Logo'
import { GlobalSearch } from './GlobalSearch'
import { useCanSearch, useSearchShortcut } from '../hooks/useGlobalSearch'
import { AppBackdrop, AmbientScreen, IconButton, PageTransition } from './motion'
import { useBootSequence } from '../hooks/useBootSequence'
import { useMagnetic } from '../hooks/useMagnetic'
import { navDirection } from '../lib/viewTransition'
import { useTheme } from '../contexts/ThemeContext'
import { cn } from '../lib/utils'
import { useAuth } from '../contexts/AuthContext'
import { useMobile } from '../contexts/MobileContext'
import { navGroups, resolveActiveNavId, allNavItems, pageTitle } from '../pages/routes'

export function AppShell() {
  const { t } = useTranslation()
  const location = useLocation()
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { isMobile } = useMobile()
  const { effects } = useTheme()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  // Phone menu sections: each time the menu opens, only the one holding the current page is unfolded.
  const [openGroups, setOpenGroups] = useState([])
  const canSearch = useCanSearch()
  const openSearch = useCallback(() => {
    setMobileMenuOpen(false)
    setSearchOpen(true)
  }, [])
  useSearchShortcut(openSearch, canSearch)
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

  useEffect(() => {
    document.title = pageTitle(location.pathname, t)
    return () => { document.title = 'Pelagos' }
  }, [location.pathname, t])

  const groups = useMemo(
    () => navGroups.map((g) => ({ ...g, items: visibleItems.filter((i) => i.group === g.id) })).filter((g) => g.items.length > 0),
    [visibleItems],
  )
  const activeItem = allNavItems.find((i) => i.id === activeId)
  useEffect(() => {
    if (mobileMenuOpen) setOpenGroups(activeItem ? [activeItem.group] : [])
  }, [mobileMenuOpen]) // eslint-disable-line react-hooks/exhaustive-deps
  const toggleGroup = (id) => setOpenGroups((prev) => (prev.includes(id) ? prev.filter((g) => g !== id) : [...prev, id]))

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
            {canSearch && <IconButton icon={MagnifyingGlass} label={t('search.title')} size="sm" onClick={openSearch} data-testid="global-search-open" />}
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
                {groups.map((group) => {
                  const open = openGroups.includes(group.id)
                  const v6 = group.id === 'dhcpv6'
                  return (
                    <div key={group.id} className="mb-1" data-testid={`menu-group-${group.id}`}>
                      <button
                        type="button"
                        onClick={() => toggleGroup(group.id)}
                        aria-expanded={open}
                        className="w-full flex items-center gap-1 px-1 py-1 text-3xs font-semibold text-text-tertiary uppercase tracking-wider rounded-md hover:bg-bg-tertiary"
                      >
                        <span className="flex-1 text-left">{t(group.labelKey)}</span>
                        <CaretDown size={10} weight="bold" className={cn('shrink-0 opacity-60', !open && '-rotate-90')} aria-hidden="true" />
                      </button>
                      {open && (
                        <div className="grid grid-cols-4 gap-1">
                          {group.items.map((item) => {
                            const Icon = item.icon
                            const active = activeId === item.id
                            return (
                              <Link key={item.id} to={item.path} className={cn('flex flex-col items-center gap-0.5 p-1.5 rounded-lg text-center', active ? 'bg-accent-primary-op15 text-accent-primary' : 'text-text-secondary')} aria-current={active ? 'page' : undefined} data-nav={item.id}>
                                <span className="relative">
                                  {Icon && <Icon size={18} weight={active ? 'fill' : 'regular'} />}
                                  {v6 && <span className="absolute -top-1 -right-3 rounded px-0.5 text-[8px] font-bold leading-tight bg-accent-primary-op15 text-accent-primary" data-testid="menu-v6-badge">v6</span>}
                                </span>
                                <span className="text-3xs font-medium leading-tight">{t(item.labelKey)}</span>
                              </Link>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )
                })}
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
              <Sidebar activeId={activeId} onSearch={canSearch ? openSearch : undefined} />
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
      {canSearch && <GlobalSearch open={searchOpen} onOpenChange={setSearchOpen} />}
    </div>
  )
}

export default AppShell
