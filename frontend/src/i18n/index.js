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

export const languages = [
  { code: 'en', name: 'English' },
  { code: 'fr', name: 'Français' },
]

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

export default i18n
