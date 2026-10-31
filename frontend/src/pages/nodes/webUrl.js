// A node's web_url becomes a link only when it is a plain http(s) URL with a host.
export function safeWebUrl(value) {
  if (typeof value !== 'string' || !value || value.length > 2048) return null
  // eslint-disable-next-line no-control-regex
  if (/[\s\x00-\x1f\x7f\\]/.test(value)) return null
  try {
    const u = new URL(value)
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname ? value : null
  } catch {
    return null
  }
}
