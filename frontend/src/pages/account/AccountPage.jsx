// SPDX-License-Identifier: Apache-2.0
// Account: profile, password change, TOTP enrollment (QR code of the otpauth URL,
// manual secret, confirmation code) or removal, and preferences (theme family,
// mode, language, animations) saved to the server through the preferences store.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { UserCircle, Key, ShieldCheck, Palette } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, Input, Select } from '../../components'
import { useAuth } from '../../contexts/AuthContext'
import { useTheme } from '../../contexts/ThemeContext'
import { useMotion } from '../../contexts/MotionContext'
import { useNotification } from '../../contexts/NotificationContext'
import { languages } from '../../i18n'
import { persistPreference } from '../../stores/preferencesStore'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate } from '../../lib/utils'
import { passwordProblem } from '../../lib/password'
import { TotpQr } from './TotpQr'

function Section({ icon: Icon, title, children, testId }) {
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid={testId}>
      <h3 className="ui-card-title flex items-center gap-2 text-sm font-semibold text-text-primary">
        <Icon size={16} className="text-accent-primary" />
        {title}
      </h3>
      {children}
    </Card>
  )
}

function PasswordSection() {
  const { t } = useTranslation('account')
  const { updateUser } = useAuth()
  const { showSuccess } = useNotification()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [errors, setErrors] = useState({})
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    const local = {}
    if (!current) local.current = t('password.errors.current')
    const problem = passwordProblem(next)
    if (problem) local.next = t(`password.errors.${problem}`)
    else if (next === current) local.next = t('password.errors.same')
    if (confirm !== next) local.confirm = t('password.errors.mismatch')
    setErrors(local)
    if (Object.keys(local).length) return
    setBusy(true)
    try {
      await api.auth.changePassword(current, next)
      updateUser({ must_change_password: false })
      setCurrent('')
      setNext('')
      setConfirm('')
      showSuccess(t('password.changed'))
    } catch (err) {
      setErrors(err?.code === 'invalid_credentials' ? { current: t('password.errors.wrong') } : { form: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Section icon={Key} title={t('password.title')} testId="account-password">
      <form onSubmit={submit} className="space-y-3 max-w-md">
        <Input label={t('password.current')} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} error={errors.current} autoComplete="current-password" data-testid="password-current" />
        <Input label={t('password.new')} type="password" value={next} onChange={(e) => setNext(e.target.value)} error={errors.next} showStrength autoComplete="new-password" helperText={t('password.policy')} data-testid="password-new" />
        <Input label={t('password.confirm')} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={errors.confirm} autoComplete="new-password" data-testid="password-confirm" />
        {errors.form && <p className="text-sm status-danger-text" role="alert">{errors.form}</p>}
        <Button type="submit" size="sm" loading={busy} data-testid="password-submit">{t('password.submit')}</Button>
      </form>
    </Section>
  )
}

function TotpSection() {
  const { t } = useTranslation('account')
  const { user, updateUser } = useAuth()
  const { showSuccess } = useNotification()
  const [enrollment, setEnrollment] = useState(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const enabled = Boolean(user?.has_totp)

  const run = async (fn) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (err) {
      setError(err?.code === 'validation_error' && err.errors?.[0]?.field === 'code' ? t('totp.errors.code') : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }
  const start = () => run(async () => setEnrollment(await api.auth.totpEnroll()))
  const confirmCode = (e) => {
    e.preventDefault()
    if (!/^\d{6}$/.test(code)) return setError(t('totp.errors.code'))
    return run(async () => {
      await api.auth.totpConfirm(code)
      updateUser({ has_totp: true })
      setEnrollment(null)
      setCode('')
      showSuccess(t('totp.enabledToast'))
    })
  }
  const disable = (e) => {
    e.preventDefault()
    if (!password) return setError(t('totp.errors.password'))
    return run(async () => {
      await api.auth.totpDisable(password)
      updateUser({ has_totp: false })
      setPassword('')
      showSuccess(t('totp.disabledToast'))
    })
  }

  return (
    <Section icon={ShieldCheck} title={t('totp.title')} testId="account-totp">
      <div className="flex items-center gap-2">
        <Badge variant={enabled ? 'success' : 'secondary'} size="sm" dot>{enabled ? t('totp.on') : t('totp.off')}</Badge>
        <span className="text-xs text-text-secondary">{t('totp.help')}</span>
      </div>
      {enabled ? (
        <form onSubmit={disable} className="space-y-3 max-w-md">
          <Input label={t('totp.password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" data-testid="totp-password" />
          {error && <p className="text-sm status-danger-text" role="alert">{error}</p>}
          <Button type="submit" size="sm" variant="danger-soft" loading={busy} data-testid="totp-disable">{t('totp.disable')}</Button>
        </form>
      ) : enrollment ? (
        <form onSubmit={confirmCode} className="space-y-3" data-testid="totp-enrollment">
          <ol className="list-decimal ml-5 text-xs text-text-secondary space-y-0.5">
            <li>{t('totp.step1')}</li>
            <li>{t('totp.step2')}</li>
          </ol>
          <div className="flex flex-wrap items-start gap-4">
            <TotpQr value={enrollment.otpauth_url} label={t('totp.qrAlt')} />
            <div className="space-y-2 min-w-0 flex-1">
              <div>
                <span className="block text-2xs uppercase tracking-wider text-text-tertiary">{t('totp.secret')}</span>
                <code className="font-mono text-sm break-all text-text-primary select-all" data-testid="totp-secret">{enrollment.secret}</code>
              </div>
              <Input label={t('totp.code')} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" className="max-w-[12rem]" data-testid="totp-code" />
              {error && <p className="text-sm status-danger-text" role="alert">{error}</p>}
              <div className="flex gap-2">
                <Button type="submit" size="sm" loading={busy} data-testid="totp-confirm">{t('totp.confirm')}</Button>
                <Button size="sm" variant="secondary" onClick={() => { setEnrollment(null); setError(null) }}>{t('common:actions.cancel')}</Button>
              </div>
            </div>
          </div>
        </form>
      ) : (
        <div className="space-y-2">
          {error && <p className="text-sm status-danger-text" role="alert">{error}</p>}
          <Button size="sm" onClick={start} loading={busy} data-testid="totp-enroll">{t('totp.enable')}</Button>
        </div>
      )}
    </Section>
  )
}

function PreferencesSection() {
  const { t, i18n } = useTranslation(['account', 'common'])
  const { themeFamily, setThemeFamily, mode, setMode, themes } = useTheme()
  const { animations, setAnimations, levels } = useMotion()
  const language = i18n.language?.split('-')[0] || 'en'
  const changeLanguage = (code) => {
    i18n.changeLanguage(code)
    persistPreference('language', code)
  }
  return (
    <Section icon={Palette} title={t('preferences.title')} testId="account-preferences">
      <p className="text-xs text-text-secondary">{t('preferences.help')}</p>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 max-w-4xl">
        <Select label={t('common:theme.family')} options={themes.map((th) => ({ value: th.id, label: th.name }))} value={themeFamily} onChange={setThemeFamily} />
        <Select label={t('common:theme.mode')} options={['system', 'dark', 'light'].map((m) => ({ value: m, label: t(`common:theme.${m}`) }))} value={mode} onChange={setMode} />
        <Select label={t('common:language.label')} options={languages.map((l) => ({ value: l.code, label: l.name }))} value={language} onChange={changeLanguage} />
        <div data-testid="pref-animations">
          <Select
            label={t('common:theme.animations')}
            options={levels.map((l) => ({ value: l, label: t(`common:theme.animationLevels.${l}`) }))}
            value={animations}
            onChange={setAnimations}
          />
        </div>
      </div>
      <p className="text-xs text-text-tertiary">{t('preferences.animationsHelp')}</p>
      <div className="flex flex-wrap gap-2" data-testid="theme-swatches">
        {themes.map((th) => (
          <button
            key={th.id}
            type="button"
            onClick={() => setThemeFamily(th.id)}
            className={`flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs ${th.id === themeFamily ? 'border-accent-primary text-text-primary' : 'border-border text-text-secondary'}`}
            aria-pressed={th.id === themeFamily}
            data-theme-swatch={th.id}
          >
            <span className="w-3 h-3 rounded-full" style={{ background: th.accent }} />
            {th.name}
          </button>
        ))}
      </div>
    </Section>
  )
}

export default function AccountPage() {
  const { t } = useTranslation(['account', 'common'])
  const { user, node } = useAuth()
  const mustChange = Boolean(user?.must_change_password)

  return (
    <PageLayout icon={UserCircle} title={t('pages.account.title')} subtitle={t('pages.account.subtitle')} testId="page-account-account">
      <div className="space-y-4 max-w-4xl">
        {mustChange && (
          <div className="rounded-lg border status-warning-border status-warning-bg px-3 py-2 text-sm status-warning-text" role="status" data-testid="account-must-change">
            {t('password.mustChange')}
          </div>
        )}
        <Section icon={UserCircle} title={t('profile.title')} testId="account-profile">
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div>
              <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('profile.username')}</dt>
              <dd className="font-medium text-text-primary">{user?.username}</dd>
            </div>
            <div>
              <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('profile.roles')}</dt>
              <dd className="flex flex-wrap gap-1">{(user?.roles || []).map((r) => <Badge key={r} size="sm" variant="secondary">{r}</Badge>)}</dd>
            </div>
            <div>
              <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('profile.lastLogin')}</dt>
              <dd className="text-text-primary">{formatDate(user?.last_login)}</dd>
            </div>
            <div>
              <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('profile.node')}</dt>
              <dd className="text-text-primary">{node?.peer?.name || '-'}</dd>
            </div>
          </dl>
          <p className="text-xs text-text-tertiary">{t('profile.sessionNote')}</p>
        </Section>
        <PasswordSection />
        <TotpSection />
        <PreferencesSection />
      </div>
    </PageLayout>
  )
}
