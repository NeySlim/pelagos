import { describe, expect, it } from 'vitest'
import { safeWebUrl } from './webUrl'

describe('safeWebUrl', () => {
  it('keeps http and https URLs', () => {
    expect(safeWebUrl('https://ns1.example.lan:8443')).toBe('https://ns1.example.lan:8443')
    expect(safeWebUrl('http://192.0.2.10:8443/')).toBe('http://192.0.2.10:8443/')
  })
  it.each(['javascript:alert(1)', 'JaVaScript:alert(1)', 'data:text/html,x', 'ftp://h/', 'https://', '//h/x', 'https://a\\@evil.example', 'https://h/\x7f', '', null, undefined, 42])(
    'drops %s',
    (v) => expect(safeWebUrl(v)).toBeNull(),
  )
  it('drops overlong values', () => {
    expect(safeWebUrl('https://h/' + 'a'.repeat(2100))).toBeNull()
  })
})
