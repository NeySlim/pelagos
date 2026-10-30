// SPDX-License-Identifier: Apache-2.0
// Checkbox list of roles (built-in first) for the user form.
import { useTranslation } from 'react-i18next'
import { roleDescription } from './validation'

export function RoleChecklist({ roles, value, onChange }) {
  const { t } = useTranslation('admin')
  const sorted = [...roles].sort((a, b) => Number(b.builtin) - Number(a.builtin) || a.name.localeCompare(b.name))
  const toggle = (name) => onChange(value.includes(name) ? value.filter((r) => r !== name) : [...value, name])
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5" data-testid="role-checklist">
      {sorted.map((role) => (
        <label key={role.name} className="flex items-start gap-2 rounded-md border border-border px-2 py-1.5 cursor-pointer hover:bg-bg-tertiary">
          <input type="checkbox" className="mt-0.5" checked={value.includes(role.name)} onChange={() => toggle(role.name)} data-role={role.name} />
          <span className="min-w-0">
            <span className="block text-sm text-text-primary font-mono">{role.name}</span>
            {role.description && <span className="block text-2xs text-text-tertiary">{roleDescription(role, t)}</span>}
          </span>
        </label>
      ))}
    </div>
  )
}

export default RoleChecklist
