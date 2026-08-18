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

// ---- resource CRUD (accounts / policy groups / endpoints / api keys) ---------
//
// State-changing calls (POST/PATCH/DELETE) fetch a fresh CSRF token bound to the
// session and send it in X-CSRF-Token, matching the admin middleware.

async function mutate<T>(method: string, path: string, body?: unknown): Promise<T> {
  const csrf = await csrfToken()
  return request<T>(method, path, body, csrf)
}

// accounts
export interface Account {
  id: string
  label: string
  account_id: string
  state: string
  concurrency_cap: number
  created_at: string
  updated_at: string
}
export const listAccounts = () => get<{ accounts: Account[] }>('/admin/api/accounts')
export const importAccount = (content: string, label: string) =>
  mutate<Account>('POST', '/admin/api/accounts/import', { content, label })

// ---- interactive OAuth login ("sign in with ChatGPT") ----
//
// begin starts the browser OAuth flow and returns an authorize URL to open plus a
// login id; the SPA opens the URL, then polls oauthLoginStatus until the callback
// completes. The loopback callback (127.0.0.1:1455/1457) requires the browser to
// be on the poolgate host.
export interface OAuthLoginBegin {
  login_id: string
  authorize_url: string
}
export type OAuthLoginStatus =
  | { status: 'pending' }
  | { status: 'success'; account: Account }
  | { status: 'error'; error: string }
export const beginOAuthLogin = (label: string) =>
  mutate<OAuthLoginBegin>('POST', '/admin/api/accounts/login/begin', { label })
export const oauthLoginStatus = (id: string) =>
  get<OAuthLoginStatus>('/admin/api/accounts/login/status?id=' + encodeURIComponent(id))

// Headless (paste) flow for a browser that is NOT on the poolgate host: begin
// returns an authorize URL to open; after signing in the operator pastes the
// redirect URL (which the loopback listener never received) back to complete.
export const beginOAuthLoginManual = (label: string) =>
  mutate<OAuthLoginBegin>('POST', '/admin/api/accounts/login/manual/begin', { label })
export const completeOAuthLoginManual = (loginId: string, redirected: string) =>
  mutate<Account>('POST', '/admin/api/accounts/login/manual/complete', {
    login_id: loginId,
    redirected,
  })
export const patchAccount = (id: string, patch: { label?: string; concurrency_cap?: number }) =>
  mutate<Account>('PATCH', `/admin/api/accounts/${encodeURIComponent(id)}`, patch)
export const deleteAccount = (id: string) =>
  mutate<void>('DELETE', `/admin/api/accounts/${encodeURIComponent(id)}`)

// policy groups
export interface PolicyGroup {
  id: string
  name: string
  strategy: string
  member_account_ids: string[]
  member_weights?: Record<string, number>
}
export const STRATEGIES = ['fallback', 'best-quota', 'load-balance', 'weighted'] as const
export const listPolicyGroups = () => get<{ policy_groups: PolicyGroup[] }>('/admin/api/policy_groups')
export const createPolicyGroup = (
  name: string,
  strategy: string,
  members: string[],
  memberWeights?: Record<string, number>,
) =>
  mutate<PolicyGroup>('POST', '/admin/api/policy_groups', {
    name,
    strategy,
    member_account_ids: members,
    member_weights: memberWeights,
  })
export const patchPolicyGroup = (
  id: string,
  patch: { strategy?: string; member_account_ids?: string[]; member_weights?: Record<string, number> },
) => mutate<PolicyGroup>('PATCH', `/admin/api/policy_groups/${encodeURIComponent(id)}`, patch)
export const deletePolicyGroup = (id: string) =>
  mutate<void>('DELETE', `/admin/api/policy_groups/${encodeURIComponent(id)}`)

// endpoints
export interface Endpoint {
  name: string
  group_id: string
}
export const listEndpoints = () => get<{ endpoints: Endpoint[] }>('/admin/api/endpoints')
export const createEndpoint = (name: string, groupID: string) =>
  mutate<Endpoint>('POST', '/admin/api/endpoints', { name, group_id: groupID })
export const deleteEndpoint = (name: string) =>
  mutate<void>('DELETE', `/admin/api/endpoints/${encodeURIComponent(name)}`)

// api keys
export interface ApiKey {
  id: string
  label: string
  endpoints: string[]
  key_masked: string
  expires_at?: string // RFC3339; absent = never expires
  ip_allowlist: string[] // empty = any IP
  key?: string // present only in the one-time create/rotate response
}
export const listApiKeys = () => get<{ api_keys: ApiKey[] }>('/admin/api/api_keys')
export const createApiKey = (
  label: string,
  endpoints: string[],
  opts: { expiresAt?: string; ipAllowlist?: string[] } = {},
) =>
  mutate<ApiKey>('POST', '/admin/api/api_keys', {
    label,
    endpoints,
    expires_at: opts.expiresAt ?? '',
    ip_allowlist: opts.ipAllowlist ?? [],
  })
export const rotateApiKey = (id: string) =>
  mutate<ApiKey>('POST', `/admin/api/api_keys/${encodeURIComponent(id)}/rotate`)
export const deleteApiKey = (id: string) =>
  mutate<void>('DELETE', `/admin/api/api_keys/${encodeURIComponent(id)}`)

// ---- notifications ------------------------------------------------------------
//
// Channel Config carries secrets (webhook URL, signing secret) and is write-only:
// it is supplied on create/patch but NEVER returned. The list/get response is the
// secret-free projection below.

export type NotifyChannelType = 'dingtalk' | 'wecom' | 'webhook'
export const CHANNEL_TYPES: NotifyChannelType[] = ['dingtalk', 'wecom', 'webhook']

// The alertable event kinds (must match model.NotifyEventKind). An empty
// selection on a channel means "all events".
export const EVENT_KINDS = [
  'account_expired',
  'account_cooldown',
  'account_quota_exhausted',
  'account_recovered',
  'quota_low',
  'policy_no_healthy_member',
  'auth_anomaly',
  'startup_bind_warning',
] as const
export type NotifyEventKind = (typeof EVENT_KINDS)[number]

export interface NotifyChannel {
  id: string
  type: NotifyChannelType
  name: string
  enabled: boolean
  events: NotifyEventKind[]
  min_headroom: number
  dedup_seconds: number
  created_at: string
  updated_at: string
}

// NotifyConfigInput is the secret-carrying config sub-object (write-only).
export interface NotifyConfigInput {
  url: string
  secret?: string
  method?: string
  headers?: Record<string, string>
  template?: string
}

export interface NotifyChannelCreate {
  type: NotifyChannelType
  name: string
  enabled?: boolean
  events?: NotifyEventKind[]
  min_headroom?: number
  dedup_seconds?: number
  config: NotifyConfigInput
}

export const listNotifyChannels = () =>
  get<{ channels: NotifyChannel[] }>('/admin/api/notify/channels')
export const createNotifyChannel = (body: NotifyChannelCreate) =>
  mutate<NotifyChannel>('POST', '/admin/api/notify/channels', body)
export const deleteNotifyChannel = (id: string) =>
  mutate<void>('DELETE', `/admin/api/notify/channels/${encodeURIComponent(id)}`)
export const setNotifyChannelEnabled = (id: string, enabled: boolean) =>
  mutate<NotifyChannel>('PATCH', `/admin/api/notify/channels/${encodeURIComponent(id)}`, { enabled })
// testNotifyChannel sends a synthetic alert to verify delivery. 502 = the channel
// is misconfigured (upstream rejected); 503 = notifications are not enabled.
export const testNotifyChannel = (id: string) =>
  mutate<{ ok: boolean }>('POST', `/admin/api/notify/channels/${encodeURIComponent(id)}/test`)

// ---- real-time monitor --------------------------------------------------------
//
// Records are secret-free (id/label only). The same filter facets narrow the
// history query, the counters, and the live SSE stream so the three views agree.

export interface RequestLog {
  id: string
  at: string
  endpoint: string
  policy: string
  account_id: string
  account_label: string
  model: string
  api_key_id: string
  api_key_label: string
  session_id: string
  status: number
  latency_ms: number
  tokens_in: number
  tokens_out: number
  trace: string
  error_type: string
}

export interface RequestCounters {
  total: number
  success: number
  error: number
  tokens_in: number
  tokens_out: number
}

export interface MonitorFilter {
  session?: string
  api_key?: string
  model?: string
  endpoint?: string
  account?: string
  status?: string
  limit?: number
}

// monitorQuery builds the shared query string; blank facets are omitted so the
// backend treats them as "no filter".
function monitorQuery(f: MonitorFilter): string {
  const q = new URLSearchParams()
  if (f.session) q.set('session', f.session)
  if (f.api_key) q.set('api_key', f.api_key)
  if (f.model) q.set('model', f.model)
  if (f.endpoint) q.set('endpoint', f.endpoint)
  if (f.account) q.set('account', f.account)
  if (f.status) q.set('status', f.status)
  if (f.limit) q.set('limit', String(f.limit))
  const s = q.toString()
  return s ? `?${s}` : ''
}

export const listRequestLogs = (f: MonitorFilter) =>
  get<{ logs: RequestLog[] }>('/admin/api/monitor/logs' + monitorQuery(f))
export const getMonitorCounters = (f: MonitorFilter) =>
  get<RequestCounters>('/admin/api/monitor/counters' + monitorQuery(f))
// monitorStreamURL is the same-origin SSE endpoint; EventSource carries the
// session cookie automatically (GET needs no CSRF).
export const monitorStreamURL = (f: MonitorFilter) =>
  '/admin/api/monitor/stream' + monitorQuery(f)

// ---- settings -----------------------------------------------------------------

export interface Settings {
  origin: string
  external_origin: string
  rp_id: string
  secure: boolean
  proxy_base: string
}
export const getSettings = () => get<Settings>('/admin/api/settings')

// revokeAllSessions signs out every session (including this one), so the caller
// must return to the login screen afterwards.
export const revokeAllSessions = () =>
  mutate<{ revoked: number }>('POST', '/admin/sessions/revoke-all', {})

// verifyAuditLog recomputes the audit log's tamper-evident hash chain.
export interface AuditVerify {
  ok: boolean
  count: number
  broken_at?: string
}
export const verifyAuditLog = () => get<AuditVerify>('/admin/api/audit/verify')

// registerAdditionalPasskey runs the session-gated registration ceremony (no
// bootstrap token): both begin and finish carry the CSRF header, which the server
// requires once a session cookie is present. No recovery codes are minted.
export async function registerAdditionalPasskey(label: string): Promise<void> {
  const csrf = await csrfToken()
  const begin = await request<BeginResp>('POST', '/admin/register/begin', { bootstrap_token: '', label }, csrf)
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
  await request(
    'POST',
    '/admin/register/finish',
    { challenge_id: begin.challenge_id, bootstrap_token: '', label, credential },
    csrf,
  )
}

