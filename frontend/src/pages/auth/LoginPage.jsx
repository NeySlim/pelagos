// SPDX-License-Identifier: Apache-2.0
// Login: username and password, then a TOTP code when the server answers
// 401 totp_required. Rate limiting (429) and bad credentials show inline.
import { Suspense, lazy, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useLocation } from 'react-router-dom'
import { LockKey, User, ShieldCheck } from '@phosphor-icons/react'
import { useAuth } from '../../contexts/AuthContext'
import { Button } from '../../components/Button'
import { Input } from '../../components/Input'
import { Logo } from '../../components/Logo'
import { AmbientScreen, AppBackdrop, Reticle } from '../../components/motion'
import { TraceScene } from './TraceScene'
import './login.css'
import { useTheme } from '../../contexts/ThemeContext'
import { errorMessage } from '../../services/apiClient'
import { languages } from '../../i18n'
import { persistPreference } from '../../stores/preferencesStore'

// The radar scene belongs to Mission Control: loaded only under its effects.
const LoginScene = lazy(() => import('./LoginScene'))

export default function LoginPage() {
  const { t, i18n } = useTranslation('auth')
  const { effects } = useTheme()
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [totpRequired, setTotpRequired] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username.trim(), password, totpRequired ? totp.trim() : undefined)
      navigate(location.state?.from && location.state.from !== '/login' ? location.state.from : '/', { replace: true })
    } catch (err) {
      if (err?.code === 'totp_required') {
        setTotpRequired(true)
        setError(totp ? t('errors.totpInvalid') : null)
      } else if (err?.code === 'invalid_credentials') {
        setError(t('errors.invalidCredentials'))
      } else if (err?.code === 'rate_limited') {
        setError(t('errors.rateLimited'))
      } else {
        setError(errorMessage(err, t('errors.generic')))
      }
    } finally {
      setBusy(false)
    }
  }

  const currentLang = i18n.language?.split('-')[0] || 'en'

  return (
    <div className="relative min-h-full flex items-center justify-center p-4 overflow-hidden" style={{ background: 'var(--gradient-bg)' }}>
      {effects === 'mission' && <AppBackdrop />}
      {effects === 'mission' && (
        <Suspense fallback={null}>
          <LoginScene />
        </Suspense>
      )}
      {effects === 'instrument' && <AmbientScreen />}
      {effects === 'instrument' && <TraceScene />}
      <div className="relative z-[1] w-full max-w-sm">
        <div className="flex justify-center mb-6">
          <Logo variant="vertical" size="lg" />
        </div>
        <Reticle tone="primary" size={14} className="login-reticle">
        <form onSubmit={handleSubmit} className="card-soft login-card p-6 space-y-4" data-testid="login-form">
          <div>
            <h1 className="ui-card-title login-card-title text-lg font-semibold text-text-primary">{t('title')}</h1>
            <p className="text-xs text-text-secondary mt-0.5">{t('subtitle')}</p>
          </div>
          <Input
            label={t('username')}
            name="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            icon={<User size={16} />}
            autoComplete="username"
            autoFocus={!totpRequired}
            required
            disabled={totpRequired}
            data-testid="login-username"
          />
          <Input
            label={t('password')}
            name="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            icon={<LockKey size={16} />}
            autoComplete="current-password"
            required
            disabled={totpRequired}
            data-testid="login-password"
          />
          {totpRequired && (
            <Input
              label={t('totpCode')}
              name="totp_code"
              value={totp}
              onChange={(e) => setTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
              icon={<ShieldCheck size={16} />}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              helperText={t('totpHint')}
              autoFocus
              required
              data-testid="login-totp"
            />
          )}
          {error && (
            <p className="text-xs status-danger-text" role="alert" data-testid="login-error">
              {error}
            </p>
          )}
          <Button type="submit" size="default" className="w-full" loading={busy} loadingText={t('signingIn')} data-testid="login-submit">
            {totpRequired ? t('verify') : t('signIn')}
          </Button>
          {totpRequired && (
            <button
              type="button"
              className="w-full text-2xs text-text-tertiary hover:text-text-primary"
              onClick={() => {
                setTotpRequired(false)
                setTotp('')
                setError(null)
              }}
            >
              {t('backToCredentials')}
            </button>
          )}
        </form>
        </Reticle>
        <div className="flex justify-center gap-3 mt-4 text-2xs text-text-tertiary">
          {languages.map((lang) => (
            <button
              key={lang.code}
              type="button"
              className={currentLang === lang.code ? 'text-accent-primary font-medium' : 'hover:text-text-primary'}
              onClick={() => {
                i18n.changeLanguage(lang.code)
                persistPreference('language', lang.code)
              }}
            >
              {lang.name}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
