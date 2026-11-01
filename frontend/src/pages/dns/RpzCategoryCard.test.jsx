// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import catalog from '../../../../backend/pelagos/rpz/catalog.json'
import '../../i18n'
import { RpzCategoryCard } from './RpzCategoryCard'

vi.mock('../../services/api', () => ({ api: { dns: { rpzEstimate: vi.fn(() => Promise.resolve({ nodes: [] })) } } }))

const copy = (o) => JSON.parse(JSON.stringify(o))

describe('RpzCategoryCard drafts', () => {
  it('keeps its draft when a refetch returns the same selection as new objects', () => {
    const onDraft = vi.fn()
    const props = { id: 'ads', catalog, nodes: [], settings: {}, canWrite: true, onDraft }
    const category = catalog.categories.ads
    const { rerender } = render(<RpzCategoryCard {...props} category={category} selection={undefined} />)
    fireEvent.click(screen.getByRole('switch'))
    expect(screen.getByTestId('rpz-category-ads')).toHaveAttribute('data-dirty', 'true')
    rerender(<RpzCategoryCard {...props} category={copy(category)} selection={undefined} />)
    expect(screen.getByTestId('rpz-category-ads')).toHaveAttribute('data-dirty', 'true')
    expect(screen.getByTestId('rpz-category-modified')).toBeInTheDocument()
  })
})
