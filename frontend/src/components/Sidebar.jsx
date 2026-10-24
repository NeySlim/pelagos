// SPDX-License-Identifier: Apache-2.0
// Grouped accordion navigation built from the area registry (pages/routes.js),
// filtered by permissions and modules; user menu with theme family, mode and language.
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { House, Gear, SignOut, Check, UserCircle, CaretRight, CaretDown, Globe, Palette, Moon, Sun, Desktop } from '@phosphor-icons/react'
import { useTheme } from '../contexts/ThemeContext'
import { useAuth } from '../contexts/AuthContext'
import { cn } from '../lib/utils'
import { Logo } from './Logo'
import { WebSocketIndicator } from './WebSocketIndicator'
import { languages } from '../i18n'
import { persistPreference } from '../stores/preferencesStore'
import { navGroups, allNavItems } from '../pages/routes'

const EXPANDED_KEY = 'pelagos-nav-expanded'

function itemClass(active) {
  return cn(
    'flex items-center gap-2 px-2 py-[5px] rounded-md text-[13px] transition-all duration-150 relative',
    active ? 'bg-accent-primary-op15 text-accent-primary font-medium' : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary',
  )
}

function NavGroup({ group, items, activeId, expanded, onToggle, t }) {
  if (items.length === 0) return null
  const groupHasActive = items.some((c) => c.id === activeId)
  return (
    <div className="w-full">
      <button
        type="button"
        onClick={onToggle}
        className={cn(
          'w-full flex items-center gap-2 px-2.5 py-[7px] rounded-md text-[11px] font-semibold tracking-wide uppercase transition-colors',
          groupHasActive ? 'text-accent-primary' : 'text-text-tertiary hover:text-text-secondary hover:bg-bg-tertiary',
        )}
        aria-expanded={expanded}
      >
        <span className="flex-1 text-left truncate">{t(group.labelKey)}</span>
        <CaretDown size={10} weight="bold" className={cn('transition-transform duration-200 shrink-0 opacity-50', !expanded && '-rotate-90')} />
      </button>
      <div className={cn('overflow-hidden transition-all duration-200 ease-out', expanded ? 'max-h-[400px] opacity-100' : 'max-h-0 opacity-0')}>
        <div className="py-0.5 pl-2 space-y-px">
          {items.map((item) => {
            const Icon = item.icon
            const active = activeId === item.id
            const label = t(item.labelKey)
            return (
              <Link key={item.id} to={item.path} title={label} className={itemClass(active)} data-nav={item.id}>
                {active && <div className="absolute left-0 w-[3px] h-4 bg-accent-primary rounded-r-full" />}
                {Icon && <Icon size={15} weight={active ? 'fill' : 'regular'} className="shrink-0" />}
                <span className="truncate">{label}</span>
              </Link>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export function useVisibleNavItems() {
  const { hasPermission, modules } = useAuth()
  return useMemo(
    () =>
      allNavItems.filter((item) => {
        if (item.permission && !hasPermission(item.permission)) return false
        if (item.module && !modules?.[item.module]) return false
        return true
      }),
    [hasPermission, modules],
  )
}

export function Sidebar({ activeId }) {
  const navigate = useNavigate()
  const { t, i18n } = useTranslation()
  const { themeFamily, setThemeFamily, mode, setMode, themes } = useTheme()
  const { user, logout, node } = useAuth()
  const visibleItems = useVisibleNavItems()

  const [expandedGroups, setExpandedGroups] = useState(() => {
    try {
      const stored = localStorage.getItem(EXPANDED_KEY)
      return stored ? JSON.parse(stored) : ['dns', 'dhcp']
    } catch {
      return ['dns', 'dhcp']
    }
  })

  const persistExpanded = (next) => {
    try {
      localStorage.setItem(EXPANDED_KEY, JSON.stringify(next))
    } catch {
      // private browsing
    }
  }

  useEffect(() => {
    const activeItem = visibleItems.find((i) => i.id === activeId)
    if (activeItem && !expandedGroups.includes(activeItem.group)) {
      setExpandedGroups((prev) => {
        const next = [...prev, activeItem.group]
        persistExpanded(next)
        return next
      })
    }
  }, [activeId]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleGroup = useCallback((groupId) => {
    setExpandedGroups((prev) => {
      const next = prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]
      persistExpanded(next)
      return next
    })
  }, [])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const currentLang = i18n.language?.split('-')[0] || 'en'
  const changeLanguage = (code) => {
    i18n.changeLanguage(code)
    persistPreference('language', code)
  }

  const dashboardItem = visibleItems.find((i) => i.id === 'dashboard')
  const accountItem = allNavItems.find((i) => i.id === 'account')
  const modeOptions = [
    { id: 'system', icon: Desktop, labelKey: 'theme.system' },
    { id: 'dark', icon: Moon, labelKey: 'theme.dark' },
    { id: 'light', icon: Sun, labelKey: 'theme.light' },
  ]

  return (
    <aside className="w-[200px] h-full border-r border-border bg-bg-secondary flex flex-col py-2.5 overflow-hidden" data-testid="sidebar">
      <Link to="/" className="flex items-center gap-2.5 px-3.5 mb-1 shrink-0" title={t('nav.dashboard')}>
        <Logo variant="icon" withText={false} size="sm" />
        <div className="flex flex-col min-w-0">
          <span className="text-xs font-bold text-text-primary leading-tight">Pelagos</span>
          <span className="text-3xs text-text-tertiary leading-tight truncate font-mono">{node?.peer?.name || node?.name || t('nav.node')}</span>
        </div>
      </Link>

      <div className="h-px bg-border mx-3 my-2 shrink-0" />

      {dashboardItem && (
        <div className="px-2 mb-1 shrink-0">
          <Link to="/" className={cn(itemClass(activeId === 'dashboard'), 'px-2.5 py-[6px] w-full')} data-nav="dashboard">
            {activeId === 'dashboard' && <div className="absolute left-0 w-[3px] h-4 bg-accent-primary rounded-r-full" />}
            <House size={15} weight={activeId === 'dashboard' ? 'fill' : 'regular'} className="shrink-0" />
            <span>{t('nav.dashboard')}</span>
          </Link>
        </div>
      )}

      <nav className="flex-1 overflow-y-auto overflow-x-hidden px-2 space-y-0.5" aria-label={t('nav.main')}>
        {navGroups.map((group) => (
          <NavGroup
            key={group.id}
            group={group}
            items={visibleItems.filter((i) => i.group === group.id)}
            activeId={activeId}
            expanded={expandedGroups.includes(group.id)}
            onToggle={() => toggleGroup(group.id)}
            t={t}
          />
        ))}
      </nav>

      <div className="shrink-0 mt-1 px-2">
        <div className="h-px bg-border mx-1 mb-1.5" />
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button type="button" className="w-full flex items-center gap-2.5 px-2 py-2 rounded-md hover:bg-bg-tertiary transition-colors" data-testid="user-menu">
              <div className="relative shrink-0">
                <div className="w-7 h-7 rounded-full bg-accent-primary-op15 border border-accent-primary-op20 flex items-center justify-center">
                  <UserCircle size={16} weight="bold" className="text-accent-primary" />
                </div>
                <WebSocketIndicator variant="dot" className="absolute -bottom-0.5 -right-0.5" />
              </div>
              <div className="flex-1 min-w-0 text-left">
                <div className="text-[13px] font-medium text-text-primary truncate">{user?.username || ''}</div>
                <div className="text-3xs text-text-tertiary truncate">{(user?.roles || []).join(', ')}</div>
              </div>
              <CaretRight size={10} className="text-text-tertiary shrink-0 opacity-60" />
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="min-w-[210px] bg-bg-secondary border border-border rounded-lg shadow-xl p-1 z-50" sideOffset={5} side="right" align="end">
              <div className="px-3 py-2 mb-1">
                <div className="text-sm font-semibold text-text-primary truncate">{user?.username}</div>
                <div className="text-xs text-text-tertiary truncate">{(user?.roles || []).join(', ')}</div>
              </div>
              <DropdownMenu.Separator className="h-px bg-border mb-1" />
              {accountItem && (
                <DropdownMenu.Item onClick={() => navigate(accountItem.path)} className="flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary">
                  <Gear size={16} />
                  <span>{t('nav.account')}</span>
                </DropdownMenu.Item>
              )}
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Label className="px-3 py-1.5 text-xs text-text-tertiary uppercase tracking-wider flex items-center gap-2">
                <Palette size={12} /> {t('theme.family')}
              </DropdownMenu.Label>
              {themes.map((theme) => (
                <DropdownMenu.Item key={theme.id} onClick={() => setThemeFamily(theme.id)} className="flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary" data-theme-option={theme.id}>
                  <div className="w-3 h-3 rounded-full border border-border" style={{ background: theme.accent }} />
                  <span className="flex-1">{theme.name}</span>
                  {themeFamily === theme.id && <Check size={16} weight="bold" className="text-accent-primary" />}
                </DropdownMenu.Item>
              ))}
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Label className="px-3 py-1.5 text-xs text-text-tertiary uppercase tracking-wider">{t('theme.mode')}</DropdownMenu.Label>
              {modeOptions.map((opt) => (
                <DropdownMenu.Item key={opt.id} onClick={() => setMode(opt.id)} className="flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary">
                  <opt.icon size={16} />
                  <span className="flex-1">{t(opt.labelKey)}</span>
                  {mode === opt.id && <Check size={16} weight="bold" className="text-accent-primary" />}
                </DropdownMenu.Item>
              ))}
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Sub>
                <DropdownMenu.SubTrigger className="flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary data-[state=open]:bg-bg-tertiary">
                  <Globe size={16} />
                  <span className="flex-1">{languages.find((l) => l.code === currentLang)?.name || 'English'}</span>
                  <CaretRight size={12} className="text-text-tertiary" />
                </DropdownMenu.SubTrigger>
                <DropdownMenu.Portal>
                  <DropdownMenu.SubContent className="min-w-[160px] bg-bg-secondary border border-border rounded-lg shadow-lg p-1 z-50">
                    {languages.map((lang) => (
                      <DropdownMenu.Item key={lang.code} onClick={() => changeLanguage(lang.code)} className="flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary">
                        <span className="flex-1">{lang.name}</span>
                        {currentLang === lang.code && <Check size={16} weight="bold" className="text-accent-primary" />}
                      </DropdownMenu.Item>
                    ))}
                  </DropdownMenu.SubContent>
                </DropdownMenu.Portal>
              </DropdownMenu.Sub>
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Item onClick={handleLogout} className="flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-status-danger-op10 text-status-danger" data-testid="logout">
                <SignOut size={16} />
                <span>{t('auth.logout')}</span>
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </aside>
  )
}
