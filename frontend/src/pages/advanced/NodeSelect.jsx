// SPDX-License-Identifier: Apache-2.0
// Node picker for the editors: nodes whose modules run the given engine.
import { useTranslation } from 'react-i18next'
import { FilterSelect } from '../../components'
import { useEngineNodes } from './useEngineNodes'

export function NodeSelect({ engine, value, onChange }) {
  const { t } = useTranslation('advanced')
  const nodes = useEngineNodes(engine)
  return (
    <FilterSelect
      value={value}
      onChange={onChange}
      options={nodes.map((n) => ({ value: n.peer.id, label: n.is_self ? `${n.peer.name} (${t('thisNode')})` : n.peer.name }))}
      placeholder={t('localNode')}
      size="sm"
    />
  )
}

export default NodeSelect
