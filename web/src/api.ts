// api.ts — the poolgate admin API client. Everything is same-origin (the SPA is
// served by the admin listener), so fetches use credentials:'include' to carry
// the session cookie. State-changing requests attach the CSRF token from
// GET /admin/csrf. The WebAuthn ceremonies convert the server's base64url option
// fields to ArrayBuffers and serialize the browser credential back to base64url.

export class ApiError extends Error {
  status: number
  type: string
  constructor(status: number, type: string, message: string) {
    super(message)
    this.status = status
    this.type = type
  }
}

// ---- base64url <-> ArrayBuffer ------------------------------------------------

export function b64urlToBuf(s: string): ArrayBuffer {
  const pad = '='.repeat((4 - (s.length % 4)) % 4)
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

export function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ---- low-level fetch ----------------------------------------------------------

async function request<T>(method: string, path: string, body?: unknown, csrf?: string): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (csrf) headers['X-CSRF-Token'] = csrf
  const resp = await fetch(path, {
    method,
    headers,
    credentials: 'include',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await resp.text()
  const data = text ? JSON.parse(text) : {}
  if (!resp.ok) {
    const err = (data && data.error) || {}
    throw new ApiError(resp.status, err.type || 'error', err.message || resp.statusText)
  }
  return data as T
}

export const get = <T>(path: string) => request<T>('GET', path)

export async function csrfToken(): Promise<string> {
  const r = await request<{ csrf_token: string }>('GET', '/admin/csrf')
  return r.csrf_token
}

// ---- auth state ---------------------------------------------------------------

export interface Me {
  authenticated: boolean
  operator: string
  session: { created_at: string; last_seen_at: string; expires_at: string }
}

// currentUser returns the operator identity if a valid session exists, else null.
export async function currentUser(): Promise<Me | null> {
  try {
    return await request<Me>('GET', '/admin/me')
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null
    throw e
  }
}

export async function logout(): Promise<void> {
  const csrf = await csrfToken()
  await request('POST', '/admin/logout', {}, csrf)
}

// ---- WebAuthn: registration ---------------------------------------------------

interface BeginResp {
  publicKey: any
  challenge_id: string
}

// register runs the first-passkey (bootstrap-gated) registration ceremony and
// returns any one-time recovery codes the server minted.
export async function register(bootstrapToken: string, label: string): Promise<{ recovery_codes?: string[] }> {
  const begin = await request<BeginResp>('POST', '/admin/register/begin', {
    bootstrap_token: bootstrapToken,
    label,
  })
  const pk = begin.publicKey
  const options: any = {
    ...pk,
    challenge: b64urlToBuf(pk.challenge),
    user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials || []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) })),
  }
  const cred = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential
  if (!cred) throw new Error('registration was cancelled')
  const att = cred.response as AuthenticatorAttestationResponse
  const credential = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64url(att.clientDataJSON),
      attestationObject: bufToB64url(att.attestationObject),
      transports: typeof att.getTransports === 'function' ? att.getTransports() : [],
    },
  }
  return request<{ recovery_codes?: string[] }>('POST', '/admin/register/finish', {
    challenge_id: begin.challenge_id,
    bootstrap_token: bootstrapToken,
    label,
    credential,
  })
}

// ---- WebAuthn: login ----------------------------------------------------------

export async function login(): Promise<void> {
  const begin = await request<BeginResp>('POST', '/admin/login/begin', {})
  const pk = begin.publicKey
  const options: any = {
    ...pk,
    challenge: b64urlToBuf(pk.challenge),
    allowCredentials: (pk.allowCredentials || []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) })),
  }
  const cred = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential
  if (!cred) throw new Error('login was cancelled')
  const asrt = cred.response as AuthenticatorAssertionResponse
  const credential = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64url(asrt.clientDataJSON),
      authenticatorData: bufToB64url(asrt.authenticatorData),
      signature: bufToB64url(asrt.signature),
      userHandle: asrt.userHandle ? bufToB64url(asrt.userHandle) : null,
    },
  }
  await request('POST', '/admin/login/finish', { challenge_id: begin.challenge_id, credential })
}

export async function loginWithRecoveryCode(code: string): Promise<void> {
  await request('POST', '/admin/login/recovery', { code })
}

// webauthnSupported reports whether the browser exposes the WebAuthn API.
export function webauthnSupported(): boolean {
  return typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

// ---- dashboard reads ----------------------------------------------------------

export interface StatusSummary {
  schema_version: number
  accounts: number
  endpoints: number
  policy_groups: number
}

export interface UsageWindow {
  name: string
  used_percent: number
  window_seconds: number
  resets_at: string
}

export interface AccountUsage {
  account_id: string
  plan_type: string
  windows: UsageWindow[]
}

export interface AccountHealth {
  account_id: string
  state: string
}

export const getStatus = () => get<StatusSummary>('/admin/api/status')
export const getUsage = () => get<{ usage: AccountUsage[] }>('/admin/api/usage')
export const getHealth = () => get<{ health: AccountHealth[] }>('/admin/api/health')

