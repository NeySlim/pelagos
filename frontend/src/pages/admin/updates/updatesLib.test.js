// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  compareVersions, engineSelection, isUnreachable, moveItem, nodeProgress, nodesBehind, parseNotes, previousVersion, rolloutActions,
  rolloutProgress, settingsChanges, settingsErrors, settingsForm, PELAGOS_STEPS, needsUnsignedConfirmation,
} from './updatesLib'

const node = (over) => ({ node_id: 'n1', state: 'pending', step: null, ...over })

describe('updatesLib', () => {
  it('compares versions numerically, a ~ suffix older', () => {
    expect(compareVersions('0.2.10', '0.2.9')).toBeGreaterThan(0)
    expect(compareVersions('0.3.0', '0.3.0')).toBe(0)
    expect(compareVersions('0.3.0~rc1', '0.3.0')).toBeLessThan(0)
    expect(compareVersions('0.2.5-1', '0.2.5')).toBe(0)
    expect(nodesBehind([{ version: '0.2.4' }, { version: '0.3.0' }], '0.3.0')).toEqual([{ version: '0.2.4' }])
  })

  it('measures node and rollout progress from the steps', () => {
    expect(nodeProgress(node({ state: 'done' }), 'pelagos')).toBe(1)
    expect(nodeProgress(node(), 'pelagos')).toBe(0)
    expect(nodeProgress(node({ state: 'running', step: 'wait' }), 'pelagos')).toBeCloseTo(0.5 / PELAGOS_STEPS.length)
    expect(nodeProgress(node({ state: 'failed', step: 'health' }), 'pelagos')).toBeCloseTo((PELAGOS_STEPS.indexOf('health') + 1) / PELAGOS_STEPS.length)
    expect(rolloutProgress({ kind: 'pelagos', nodes: [node({ state: 'done' }), node()] })).toBe(0.5)
  })

  it('offers the actions each rollout state accepts', () => {
    const done = node({ state: 'done' })
    expect(rolloutActions({ kind: 'pelagos', state: 'running', nodes: [node({ state: 'running' })] })).toEqual({ resume: false, cancel: true, rollback: false })
    expect(rolloutActions({ kind: 'pelagos', state: 'failed', nodes: [done, node({ state: 'rolled_back' })] })).toEqual({ resume: true, cancel: true, rollback: true })
    expect(rolloutActions({ kind: 'pelagos', state: 'cancelled', nodes: [done] })).toEqual({ resume: false, cancel: false, rollback: false })
    expect(rolloutActions({ kind: 'rollback', state: 'done', nodes: [done] }).rollback).toBe(false)
  })

  it('moves a node in the order and ignores moves out of range', () => {
    expect(moveItem(['a', 'b', 'c'], 2, -1)).toEqual(['a', 'c', 'b'])
    expect(moveItem(['a', 'b'], 0, -1)).toEqual(['a', 'b'])
  })

  it('treats no answer and proxy errors as the node restarting, not a 401', () => {
    expect(isUnreachable({ status: 0, code: 'network_error' })).toBe(true)
    expect(isUnreachable({ status: 502 })).toBe(true)
    expect(isUnreachable({ status: 401, code: 'unauthenticated' })).toBe(false)
  })

  it('asks the extra confirmation only for unsigned or unknown key releases', () => {
    expect(needsUnsignedConfirmation({ signature: 'valid' })).toBe(false)
    expect(needsUnsignedConfirmation({ signature: 'unsigned' })).toBe(true)
    expect(needsUnsignedConfirmation({ signature: 'unknown_key' })).toBe(true)
  })

  it('picks the most common kept version and the engine selection', () => {
    expect(previousVersion([{ previous_kept: '0.2.4' }, { previous_kept: '0.2.4' }, { previous_kept: '0.2.3' }])).toBe('0.2.4')
    expect(previousVersion([{ previous_kept: null }])).toBe(null)
    const engines = [
      { node_id: 'n1', package: 'bind9', candidate: '1' }, { node_id: 'n2', package: 'bind9', candidate: '1' }, { node_id: 'n1', package: 'kea', candidate: null },
    ]
    expect(engineSelection(engines, ['n1|bind9', 'n2|bind9', 'n1|kea'])).toEqual({ packages: ['bind9'], node_ids: ['n1', 'n2'] })
  })

  it('renders release notes as text blocks', () => {
    const blocks = parseNotes('# Pelagos 0.3.0\n\n- one\n- two\n\nSome text\non two lines\n\n    sha256  file.deb\n```\ncode\n```\n<script>x</script>')
    expect(blocks.map((b) => b.type)).toEqual(['h', 'li', 'li', 'p', 'code', 'code', 'p'])
    expect(blocks[3].text).toBe('Some text on two lines')
    expect(blocks[6].text).toBe('<script>x</script>')
  })

  it('validates and diffs the source settings', () => {
    const settings = { source: 'upload', check_interval_hours: 24, settle_seconds: 30, timeout_seconds: 300, pause_seconds: 60, keep_packages_count: 2, auto_rollback_enabled: true, check_enabled: true, github_repository: '' }
    const form = settingsForm(settings)
    expect(settingsChanges(form, settings)).toEqual({})
    expect(settingsErrors({ ...form, source: 'github' })).toEqual({ github_repository: { code: 'repositoryRequired' } })
    expect(settingsErrors({ ...form, pause_seconds: '9999' }).pause_seconds.code).toBe('range')
    expect(settingsChanges({ ...form, pause_seconds: '90', github_repository: 'example/pelagos' }, settings)).toEqual({ pause_seconds: 90, github_repository: 'example/pelagos' })
  })
})
