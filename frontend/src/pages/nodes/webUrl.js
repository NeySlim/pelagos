// A node's web_url becomes a link only when it is a plain http(s) URL with a host.
export function safeWebUrl(value) {
  if (typeof value !== 'string' || !value || value.length > 2048) return null
  try {
    const u = new URL(value)
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname ? value : null
  } catch {
    return null
  }
}
