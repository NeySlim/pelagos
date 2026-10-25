// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { act, render } from '@testing-library/react'

const bus = vi.hoisted(() => new Map())
vi.mock('../../hooks/useWebSocket', async () => {
  const { useEffect, useRef } = await import('react')
  return {
    useWsTopic: (topic, handler) => {
      const ref = useRef(handler)
      ref.current = handler
      useEffect(() => {
        if (!topic) return undefined
        const fn = (m) => ref.current?.(m)
        bus.set(topic, fn)
        return () => bus.delete(topic)
      }, [topic])
    },
  }
})
const { sameZone, useZoneEvents } = await import('./zoneEvents')

function Probe({ zone, view, onEvent }) {
  useZoneEvents(zone, view, onEvent)
  return null
}

describe('zone events', () => {
  it('matches the zone with or without its final dot, in its view', () => {
    expect(sameZone({ zone: 'example.lan.', view: '_default' }, 'example.lan', '_default')).toBe(true)
    expect(sameZone({ zone: 'Example.lan' }, 'example.lan.', '_default')).toBe(true)
    expect(sameZone({ zone: 'example.lan.', view: 'internal' }, 'example.lan.', '_default')).toBe(false)
    expect(sameZone({ zone: 'corp.example.lan.', view: '_default' }, 'example.lan.', '_default')).toBe(false)
    expect(sameZone(null, 'example.lan.')).toBe(false)
  })

  it('calls back for a serial or transfer of this zone only, once the zone is known', () => {
    const onEvent = vi.fn()
    const { rerender } = render(<Probe zone={undefined} view={undefined} onEvent={onEvent} />)
    expect(bus.has('zones')).toBe(false)
    rerender(<Probe zone="example.lan." view="_default" onEvent={onEvent} />)
    const send = (event, data) => act(() => bus.get('zones')({ topic: 'zones', event, node_id: 'n2', data }))
    send('transfer', { zone: 'example.lan.', view: '_default', kind: 'secondary', serial: 2 })
    send('serial', { zone: 'other.lan.', view: '_default', kind: 'primary', serial: 3 })
    expect(onEvent).toHaveBeenCalledTimes(1)
    expect(onEvent.mock.calls[0][0].event).toBe('transfer')
  })
})
