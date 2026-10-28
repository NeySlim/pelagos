// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { b64urlToBuffer, bufferToB64url, cancelled, credentialToJSON, toCreationOptions, toRequestOptions } from './webauthn'

const bytes = (...b) => new Uint8Array(b).buffer

describe('webauthn glue', () => {
  it('round-trips base64url without padding', () => {
    for (const text of ['', 'AA', 'AAE', '_-8', 'aGVsbG8gd29ybGQ']) {
      expect(bufferToB64url(b64urlToBuffer(text))).toBe(text)
    }
    expect(bufferToB64url(bytes(0xfb, 0xff))).toBe('-_8')
  })

  it('turns the server options into buffers', () => {
    const create = toCreationOptions({ challenge: 'AQID', rp: { id: 'example.lan', name: 'Pelagos' }, user: { id: 'VTE', name: 'alice' }, excludeCredentials: [{ type: 'public-key', id: 'BAU', transports: ['usb'] }] })
    expect(new Uint8Array(create.challenge)).toEqual(new Uint8Array([1, 2, 3]))
    expect(new TextDecoder().decode(create.user.id)).toBe('U1')
    expect(create.excludeCredentials[0].transports).toEqual(['usb'])
    const get = toRequestOptions({ challenge: 'AQID', rpId: 'example.lan' })
    expect(get.allowCredentials).toEqual([])
  })

  it('serializes registration and assertion answers', () => {
    const reg = credentialToJSON({
      id: 'BAU', rawId: bytes(4, 5), type: 'public-key',
      response: { clientDataJSON: bytes(1), attestationObject: bytes(2), getTransports: () => ['usb'], getPublicKey: () => bytes(3), getPublicKeyAlgorithm: () => -7 },
      getClientExtensionResults: () => ({}),
    })
    expect(reg.response).toEqual({ clientDataJSON: 'AQ', attestationObject: 'Ag', transports: ['usb'], publicKey: 'Aw', publicKeyAlgorithm: -7 })
    const get = credentialToJSON({
      id: 'BAU', rawId: bytes(4, 5), type: 'public-key',
      response: { clientDataJSON: bytes(1), authenticatorData: bytes(2), signature: bytes(3), userHandle: null },
      getClientExtensionResults: () => { throw new Error('old browser') },
    })
    expect(get.response).toEqual({ clientDataJSON: 'AQ', authenticatorData: 'Ag', signature: 'Aw', userHandle: null })
    expect(get.clientExtensionResults).toEqual({})
  })

  it('tells a closed prompt from a failure', () => {
    expect(cancelled({ name: 'NotAllowedError' })).toBe(true)
    expect(cancelled(new Error('x'))).toBe(false)
  })
})
