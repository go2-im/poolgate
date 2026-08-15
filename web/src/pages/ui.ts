// ui.ts — small shared presentation helpers (no inline styles; CSP-safe).

// stateClass maps an account state to a pill CSS class.
export function stateClass(state: string): string {
  if (state === 'ok') return 'pill ok'
  if (state === 'unknown') return 'pill'
  if (state === 'revoked' || state === 'dead' || state === 'expired') return 'pill bad'
  return 'pill warn'
}

// errMessage extracts a human message from a thrown value.
export function errMessage(e: unknown): string {
  if (e instanceof Error) return e.message
  return 'unexpected error'
}

// copy writes text to the clipboard (best-effort; localhost is a secure context).
export async function copy(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // ignore — clipboard may be unavailable; the value is still visible on screen.
  }
}
