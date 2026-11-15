// Hex helpers (no libsodium dependency).

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim()
  if (clean.length % 2 !== 0) throw new Error('Hex string has odd length')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    const v = parseInt(clean.substr(i, 2), 16)
    if (Number.isNaN(v)) throw new Error(`Invalid hex at position ${i}`)
    bytes[i / 2] = v
  }
  return bytes
}

export function shortHex(hex: string, chars = 12): string {
  if (!hex) return ''
  return hex.length > chars * 2 ? `${hex.slice(0, chars)}…${hex.slice(-chars)}` : hex
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
