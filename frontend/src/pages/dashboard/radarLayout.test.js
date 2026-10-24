// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  alertMarkers, beamDuration, blipPoint, haTone, linkDuration, linkState, nodeAngles, nodeTone, polar, project, radarFrame, segment, utilizationSegments,
} from './radarLayout'

const close = (a, b) => expect(Math.abs(a - b)).toBeLessThan(1e-9)

describe('radar geometry', () => {
  it('places one node in front and a pair face to face', () => {
    expect(nodeAngles(0)).toEqual([])
    expect(nodeAngles(1)).toEqual([90])
    expect(nodeAngles(2)).toEqual([180, 0])
    const three = nodeAngles(3)
    expect(three).toHaveLength(3)
    expect(new Set(three).size).toBe(3)
  })

  it('projects floor points with the squash on Y', () => {
    const frame = radarFrame(500, 300, { squash: 0.5, top: 50, bottom: 50, side: 0 })
    expect(frame).toMatchObject({ cx: 250, cy: 150, r: 200 })
    const p = project(polar(90, 1), frame)
    close(p.left, 250)
    close(p.top, 250)
    expect(project({ x: -1, y: 0 }, frame)).toEqual({ left: 50, top: 150 })
  })

  it('fits the disc in the narrower dimension', () => {
    expect(radarFrame(1000, 200, { squash: 0.4, top: 0, bottom: 0, side: 0 }).r).toBe(250)
    expect(radarFrame(100, 1000, { squash: 0.4, top: 0, bottom: 0, side: 0 }).r).toBe(50)
    expect(radarFrame(0, 0).r).toBe(0)
  })

  it('describes a link as a rotated segment in floor percent', () => {
    const s = segment({ x: -0.5, y: 0 }, { x: 0.5, y: 0 })
    expect(s).toEqual({ left: 50, top: 50, length: 50, angle: 0 })
    expect(segment({ x: 0, y: 0 }, { x: 0, y: 1 }).angle).toBe(90)
  })

  it('places zone blips by name, inside the node ring', () => {
    const a = blipPoint('_default/example.lan.')
    expect(blipPoint('_default/example.lan.')).toEqual(a)
    expect(Math.hypot(a.x, a.y)).toBeLessThan(0.55)
  })
})

describe('radar states', () => {
  const peer = (id, status = 'online', extra = {}) => ({ peer: { id }, status, ...extra })

  it('colors nodes by status, error and critical alerts', () => {
    expect(nodeTone(peer('a', 'offline'))).toBe('danger')
    expect(nodeTone(peer('a', 'online', { error: 'boom' }))).toBe('warning')
    expect(nodeTone(peer('a'), [{ node_id: 'a', severity: 'critical' }])).toBe('warning')
    expect(nodeTone(peer('a'), [{ node_id: 'b', severity: 'critical' }])).toBe('success')
  })

  it('marks a link lagging when a serial on the peer is behind', () => {
    const zones = [{ serials: { a: 5, b: 5 } }, { serials: { a: 7, b: 6 } }]
    expect(linkState(peer('b'), zones)).toEqual({ state: 'lag', behind: 1 })
    expect(linkState(peer('a'), zones)).toEqual({ state: 'ok', behind: 0 })
    expect(linkState(peer('b', 'offline'), zones).state).toBe('down')
    expect(linkDuration('ok')).toBeLessThan(linkDuration('lag'))
    expect(linkDuration('down')).toBeNull()
  })

  it('speeds the beam up with traffic and stops it at zero', () => {
    expect(beamDuration(0)).toBeNull()
    expect(beamDuration(null)).toBeNull()
    expect(beamDuration(1000)).toBeLessThan(beamDuration(10))
    expect(beamDuration(1e9)).toBe(0.35)
  })

  it('maps HA states to waypoint tones', () => {
    expect(haTone({ state: 'hot-standby', role: 'primary', partner: { in_touch: true } })).toBe('primary')
    expect(haTone({ state: 'hot-standby', role: 'standby' })).toBe('success')
    expect(haTone({ state: 'backup', role: 'backup' })).toBe('neutral')
    expect(haTone({ state: 'syncing' })).toBe('warning')
    expect(haTone({ state: 'partner-down' })).toBe('danger')
    expect(haTone({ state: 'hot-standby', partner: { in_touch: false } })).toBe('danger')
  })

  it('puts node alerts on their pin and the others on the rim', () => {
    const { byNode, markers } = alertMarkers([{ id: 1, node_id: 'a' }, { id: 2, node_id: null }, { id: 3, node_id: 'z' }], ['a'])
    expect(byNode.a).toHaveLength(1)
    expect(markers.map((m) => m.alert.id)).toEqual([2, 3])
    // The rim markers sit on the back half of the disc (negative y).
    expect(markers.every((m) => m.point.y < 0)).toBe(true)
  })

  it('cuts a pool utilization into threshold-colored segments', () => {
    const states = utilizationSegments(95, { count: 10, warn: 80, full: 90 }).map((s) => s.state)
    expect(states).toEqual(['done', 'done', 'done', 'done', 'done', 'done', 'done', 'done', 'warning', 'current'])
    expect(utilizationSegments(100, { count: 4, warn: 50, full: 75 }).map((s) => s.state)).toEqual(['done', 'done', 'warning', 'danger'])
    expect(utilizationSegments(0, { count: 3 }).every((s) => s.state === 'next')).toBe(true)
  })
})
