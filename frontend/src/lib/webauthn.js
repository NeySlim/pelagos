// SPDX-License-Identifier: Apache-2.0
// WebAuthn glue: the server's options JSON (base64url fields) to the ArrayBuffers
// navigator.credentials wants, and the PublicKeyCredential back to JSON.

export function b64urlToBuffer(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i)
  return out.buffer
}

export function bufferToB64url(buffer) {
  const bytes = new Uint8Array(buffer)
  let bin = ''
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function webauthnSupported() {
  return typeof window !== 'undefined' && Boolean(window.PublicKeyCredential) && Boolean(navigator.credentials)
}

const descriptor = (d) => ({ ...d, id: b64urlToBuffer(d.id) })

export function toCreationOptions(json) {
  return {
    ...json,
    challenge: b64urlToBuffer(json.challenge),
    user: { ...json.user, id: b64urlToBuffer(json.user.id) },
    excludeCredentials: (json.excludeCredentials || []).map(descriptor),
  }
}

export function toRequestOptions(json) {
  return {
    ...json,
    challenge: b64urlToBuffer(json.challenge),
    allowCredentials: (json.allowCredentials || []).map(descriptor),
  }
}

function optional(fn) {
  try {
    return fn()
  } catch {
    return undefined
  }
}

export function credentialToJSON(cred) {
  const r = cred.response
  const response = { clientDataJSON: bufferToB64url(r.clientDataJSON) }
  if (r.attestationObject) {
    response.attestationObject = bufferToB64url(r.attestationObject)
    const transports = optional(() => r.getTransports?.())
    if (transports) response.transports = transports
    // SPKI of the new key: the mock server verifies assertions with it; the backend reads the COSE key.
    const spki = optional(() => r.getPublicKey?.())
    if (spki) response.publicKey = bufferToB64url(spki)
    const alg = optional(() => r.getPublicKeyAlgorithm?.())
    if (alg !== undefined) response.publicKeyAlgorithm = alg
  } else {
    response.authenticatorData = bufferToB64url(r.authenticatorData)
    response.signature = bufferToB64url(r.signature)
    response.userHandle = r.userHandle ? bufferToB64url(r.userHandle) : null
  }
  return {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    response,
    clientExtensionResults: optional(() => cred.getClientExtensionResults()) || {},
  }
}

export async function createCredential(options) {
  const cred = await navigator.credentials.create({ publicKey: toCreationOptions(options) })
  return credentialToJSON(cred)
}

export async function getCredential(options, signal) {
  const cred = await navigator.credentials.get({ publicKey: toRequestOptions(options), signal })
  return credentialToJSON(cred)
}

// A user who closes the browser prompt or lets it time out: not an error worth a red message.
export function cancelled(err) {
  return err?.name === 'NotAllowedError' || err?.name === 'AbortError'
}
