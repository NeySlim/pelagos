// SPDX-License-Identifier: Apache-2.0
// QR code of an otpauth:// URL, drawn locally as SVG (the secret never leaves the
// browser) and shown as a data: image, which the CSP allows (img-src data:).
import { useEffect, useState } from 'react'
import QRCode from 'qrcode'

function svgDataUrl(svg) {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}

export function TotpQr({ value, label, size = 176 }) {
  const [src, setSrc] = useState(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let cancelled = false
    setFailed(false)
    QRCode.toString(value, { type: 'svg', errorCorrectionLevel: 'M', margin: 2, color: { dark: '#000000', light: '#ffffff' } })
      .then((svg) => !cancelled && setSrc(svgDataUrl(svg)))
      .catch(() => !cancelled && setFailed(true))
    return () => {
      cancelled = true
    }
  }, [value])
  if (failed) return null
  return (
    <div className="rounded-lg bg-white p-1 shrink-0" style={{ width: size, height: size }}>
      {src && <img src={src} alt={label} width={size - 8} height={size - 8} data-testid="totp-qr" />}
    </div>
  )
}

export default TotpQr
