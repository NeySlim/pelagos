// SPDX-License-Identifier: Apache-2.0
// Login: username and password, then a TOTP code (401 totp_required) or a
// security key (401 second_factor_required); or a passkey without a password.
// Rate limiting (429) and bad credentials show inline.
import { Suspense, lazy, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useLocation } from 'react-router-dom'
import { LockKey, User, ShieldCheck, Fingerprint } from '@phosphor-icons/react'
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
import { api } from '../../services/api'
import { cancelled, getCredential, webauthnSupported } from '../../lib/webauthn'

// The radar scene belongs to Mission Control: loaded only under its effects.
const LoginScene = lazy(() => import('./LoginScene'))

export default function LoginPage() {
  const { t, i18n } = useTranslation('auth')
  const { effects } = useTheme()
  const { login, loginWithKey } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [totpRequired, setTotpRequired] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  // second_factor_required problem: methods, ceremony, options (a key is asked for).
  const [keyStep, setKeyStep] = useState(null)
  const [passkeys, setPasskeys] = useState(false)

  useEffect(() => {
    if (!webauthnSupported()) return undefined
    let live = true
    api.auth.webauthnSite().then((site) => live && setPasskeys(Boolean(site?.available))).catch(() => {})
    return () => {
      live = false
    }
  }, [])

  const done = () => navigate(location.state?.from && location.state.from !== '/login' ? location.state.from : '/', { replace: true })

  const failed = (err) => {
    if (cancelled(err)) setError(t('errors.keyCancelled'))
    else if (err?.code === 'invalid_credentials') setError(t('errors.keyRefused'))
    else if (err?.code === 'rate_limited') setError(t('errors.rateLimited'))
    else setError(errorMessage(err, t('errors.generic')))
  }

  // A fresh challenge for a second try: the server drops a ceremony once an answer was checked.
  const freshKeyStep = async () => {
    try {
      await login(username.trim(), password)
      done()
      return null
    } catch (err) {
      if (err?.code === 'second_factor_required' && err.problem?.ceremony) return err.problem
      throw err
    }
  }

  const answerWithKey = async (step = keyStep) => {
    setBusy(true)
    setError(null)
    try {
      const current = step.used ? await freshKeyStep() : step
      if (!current) return
      setKeyStep(current)
      const credential = await getCredential(current.options)
      setKeyStep({ ...current, used: true })
      await loginWithKey(current.ceremony, credential)
      done()
    } catch (err) {
      failed(err)
    } finally {
      setBusy(false)
    }
  }

  const passkeyLogin = async () => {
    setBusy(true)
    setError(null)
    try {
      const { ceremony, options } = await api.auth.passkeyOptions()
      const credential = await getCredential(options)
      await loginWithKey(ceremony, credential)
      done()
    } catch (err) {
      failed(err)
    } finally {
      setBusy(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username.trim(), password, totpRequired ? totp.trim() : undefined)
      done()
    } catch (err) {
      const problem = err?.problem || {}
      if (err?.code === 'second_factor_required' && problem.methods?.includes('webauthn')) {
        setTotpRequired(false)
        setKeyStep(problem)
        setError(null)
        await answerWithKey(problem)
      } else if (err?.code === 'second_factor_required' && problem.methods?.includes('totp')) {
        setTotpRequired(true)
        setError(totp ? t('errors.totpInvalid') : null)
      } else if (err?.code === 'second_factor_required') {
        setError(t('errors.keyElsewhere', { domains: (problem.rp_ids || []).join(', ') }))
      } else if (err?.code === 'totp_required') {
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
            disabled={totpRequired || Boolean(keyStep)}
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
            disabled={totpRequired || Boolean(keyStep)}
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
          {keyStep && (
            <div className="rounded-lg border border-border px-3 py-2 text-xs text-text-secondary flex items-center gap-2" data-testid="login-key-step">
              <Fingerprint size={18} className="text-accent-primary shrink-0" />
              {t('keyPrompt')}
            </div>
          )}
          {error && (
            <p className="text-xs status-danger-text" role="alert" data-testid="login-error">
              {error}
            </p>
          )}
          {keyStep ? (
            <Button type="button" size="default" className="w-full" loading={busy} loadingText={t('signingIn')} onClick={() => answerWithKey()} data-testid="login-key">
              {t('useKey')}
            </Button>
          ) : (
            <Button type="submit" size="default" className="w-full" loading={busy} loadingText={t('signingIn')} data-testid="login-submit">
              {totpRequired ? t('verify') : t('signIn')}
            </Button>
          )}
          {keyStep?.methods?.includes('totp') && (
            <button
              type="button"
              className="w-full text-2xs text-text-tertiary hover:text-text-primary"
              onClick={() => {
                setKeyStep(null)
                setTotpRequired(true)
                setError(null)
              }}
              data-testid="login-use-totp"
            >
              {t('useTotpInstead')}
            </button>
          )}
          {!keyStep && !totpRequired && passkeys && (
            <Button type="button" variant="secondary" size="default" className="w-full" disabled={busy} onClick={passkeyLogin} data-testid="login-passkey">
              <Fingerprint size={16} />
              {t('passkey')}
            </Button>
          )}
          {(totpRequired || keyStep) && (
            <button
              type="button"
              className="w-full text-2xs text-text-tertiary hover:text-text-primary"
              onClick={() => {
                setTotpRequired(false)
                setKeyStep(null)
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
