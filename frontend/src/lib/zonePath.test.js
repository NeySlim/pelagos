// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createElement } from 'react'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom'
import { ROOT_SEGMENT, zoneFromSegment, zoneSegment } from './zonePath'
import { zoneHref } from '../pages/dns/helpers'
import { subjectLink } from '../pages/alerts/lib'
import { api } from '../services/api'

const NAMES = ['.', 'example.lan.', 'example.lan', '0/25.2.0.192.in-addr.arpa.', 'xn--bcher-kva.example.', 'a_b.example.lan.']

function ShowZone() {
  return createElement('span', { 'data-testid': 'zone' }, zoneFromSegment(useParams().zone))
}

function routed(href) {
  // The router resolves the href as a browser does ("." segments included), then decodes the parameter.
  const url = new URL(href, 'http://pelagos.example')
  render(
    createElement(
      MemoryRouter,
      { initialEntries: [url.pathname + url.search] },
      createElement(Routes, null, createElement(Route, { path: '/dns/zones/:zone', element: createElement(ShowZone) })),
    ),
  )
  return screen.queryByTestId('zone')?.textContent
}

describe('zone path segments', () => {
  it('names the root zone "@", never an empty or dot segment', () => {
    expect(zoneSegment('.')).toBe(ROOT_SEGMENT)
    expect(zoneHref('.')).toBe('/dns/zones/@')
    expect(zoneHref('.', 'internal')).toBe('/dns/zones/@?view=internal')
    expect(zoneFromSegment('@')).toBe('.')
  })

  it('percent-encodes the slash of a classless reverse zone', () => {
    expect(zoneSegment('0/25.2.0.192.in-addr.arpa.')).toBe('0%2F25.2.0.192.in-addr.arpa')
  })

  it.each(NAMES)('round-trips %s through the zone detail route', (name) => {
    const want = name === '.' ? '.' : name.replace(/\.$/, '')
    expect(routed(zoneHref(name))).toBe(want)
  })

  it('links alert subjects on the root zone to its page', () => {
    expect(subjectLink({ subject: 'zone:.' }).to).toBe('/dns/zones/@')
    expect(subjectLink({ subject: 'zone:.@internal' }).to).toBe('/dns/zones/@?view=internal')
  })
})

describe('zone API paths', () => {
  const urls = []
  beforeEach(() => {
    urls.length = 0
    global.fetch = vi.fn(async (url) => {
      urls.push(url)
      return { ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => ({}) }
    })
  })

  it('reads the root and classless zones by their segment', async () => {
    await api.dns.zone('.')
    await api.dns.records('.', { page: 1 })
    await api.dns.zone('0/25.2.0.192.in-addr.arpa.')
    expect(urls[0]).toMatch(/\/dns\/zones\/@$/)
    expect(urls[1]).toMatch(/\/dns\/zones\/@\/records\?page=1$/)
    expect(urls[2]).toMatch(/\/dns\/zones\/0%2F25\.2\.0\.192\.in-addr\.arpa$/)
  })
})
