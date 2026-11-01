// SPDX-License-Identifier: Apache-2.0
// One namespace per area: src/i18n/locales/<lang>/<area>.json. Files are discovered
// with import.meta.glob, so a new area adds its two files and touches nothing shared.
// `common` holds shell and shared component strings and is the default namespace.
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

const files = import.meta.glob('./locales/*/*.json', { eager: true, import: 'default' })

export const resources = {}
for (const [path, content] of Object.entries(files)) {
  const [, lang, ns] = path.match(/\.\/locales\/([^/]+)\/([^/]+)\.json$/)
  resources[lang] = resources[lang] || {}
  resources[lang][ns] = content
}

// A language is a folder under locales/: English first (the fallback), the others by code.
// Each is named in its own language ("Français"), so a reader finds it whatever the UI language.
export function languageName(code) {
  try {
    const name = new Intl.DisplayNames([code], { type: 'language' }).of(code)
    return name ? name.charAt(0).toLocaleUpperCase(code) + name.slice(1) : code
  } catch {
    return code
  }
}

export const languages = Object.keys(resources)
  .sort((a, b) => (a === 'en' ? -1 : b === 'en' ? 1 : a.localeCompare(b)))
  .map((code) => ({ code, name: languageName(code) }))

export const namespaces = Object.keys(resources.en || {})

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    ns: namespaces,
    defaultNS: 'common',
    fallbackLng: 'en',
    supportedLngs: languages.map((l) => l.code),
    nonExplicitSupportedLngs: true,
    interpolation: { escapeValue: false },
    showSupportNotice: false,
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
    },
  })

// <html lang> follows the app language: screen reader pronunciation, native date inputs.
const syncDocumentLang = (lng) => {
  if (typeof document !== 'undefined' && lng) document.documentElement.lang = lng.split('-')[0]
}
syncDocumentLang(i18n.resolvedLanguage || i18n.language)
i18n.on('languageChanged', syncDocumentLang)

export default i18n
