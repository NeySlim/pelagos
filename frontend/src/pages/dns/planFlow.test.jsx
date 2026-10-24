// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { usePlanFlow } from './helpers'

function plan(id, summary, expiresIn) {
  return {
    id,
    scope: 'dns.rrset',
    engine: 'bind',
    summary,
    created_by: 'alice',
    changes: [],
    diff: '',
    preconditions: [],
    validations: [],
    target_node_ids: [],
    requires_confirmation: false,
    state: 'validated',
    expires_at: new Date(Date.now() + expiresIn).toISOString(),
  }
}

function Flow({ build }) {
  const { run, modal } = usePlanFlow()
  return (
    <>
      <button type="button" onClick={() => run(build)}>
        build
      </button>
      {modal}
    </>
  )
}

describe('usePlanFlow', () => {
  it('recomputes an expired plan with the same builder', async () => {
    const build = vi.fn().mockResolvedValueOnce(plan('P1', 'first', -1000)).mockResolvedValueOnce(plan('P2', 'second', 600000))
    render(<Flow build={build} />)
    fireEvent.click(screen.getByText('build'))
    await waitFor(() => expect(screen.getByTestId('plan-summary')).toHaveTextContent('first'))
    fireEvent.click(screen.getByTestId('plan-recompute'))
    await waitFor(() => expect(screen.getByTestId('plan-summary')).toHaveTextContent('second'))
    expect(build).toHaveBeenCalledTimes(2)
    expect(screen.getByTestId('plan-apply')).toBeEnabled()
  })
})
