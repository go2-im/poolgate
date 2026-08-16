import { useEffect, useState } from 'react'
import {
  createApiKey,
  deleteApiKey,
  listApiKeys,
  listEndpoints,
  rotateApiKey,
  type ApiKey,
  type Endpoint,
} from '../api'
import { copy, errMessage } from './ui'

export function ApiKeys() {
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [label, setLabel] = useState('')
  const [scoped, setScoped] = useState<string[]>([])
  const [expiresAt, setExpiresAt] = useState('')
  const [allowlist, setAllowlist] = useState('')
  const [freshKey, setFreshKey] = useState('')

  async function load() {
    setErr('')
    try {
      const [k, e] = await Promise.all([listApiKeys(), listEndpoints()])
      setKeys(k.api_keys)
      setEndpoints(e.endpoints)
    } catch (ex) {
      setErr(errMessage(ex))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  function toggleScope(name: string) {
    setScoped((s) => (s.includes(name) ? s.filter((x) => x !== name) : [...s, name]))
  }

  // parseAllowlist splits the comma/space/newline-separated IP/CIDR input into a
  // clean list; empty input means "any IP".
  function parseAllowlist(raw: string): string[] {
    return raw
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean)
  }

  // toRFC3339 converts a datetime-local value (no timezone) to an RFC3339 UTC
  // instant the backend accepts; empty means "never expires".
  function toRFC3339(local: string): string {
    if (!local) return ''
    const d = new Date(local)
    if (isNaN(d.getTime())) return local // let the backend reject a bad value
    return d.toISOString()
  }

  async function doCreate() {
    setErr('')
    setBusy(true)
    try {
      const created = await createApiKey(label.trim(), scoped, {
        expiresAt: toRFC3339(expiresAt),
        ipAllowlist: parseAllowlist(allowlist),
      })
      setFreshKey(created.key ?? '')
      setLabel('')
      setScoped([])
      setExpiresAt('')
      setAllowlist('')
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function doRotate(k: ApiKey) {
    if (!confirm(`Rotate API key "${k.label || k.id}"? The old secret stops working immediately.`)) return
    setErr('')
    try {
      const rotated = await rotateApiKey(k.id)
      setFreshKey(rotated.key ?? '')
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  async function doDelete(k: ApiKey) {
    if (!confirm(`Delete API key "${k.label || k.id}"? Clients using it will stop working.`)) return
    setErr('')
    try {
      await deleteApiKey(k.id)
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  return (
    <>
      <div className="section">
        <h2>New API key</h2>
        <p className="muted">
          An inbound <code>sk-</code> key for the proxy. Leave scope empty to allow all endpoints.
        </p>
        <label htmlFor="key-label">Label (optional)</label>
        <input
          id="key-label"
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. laptop-cursor"
          autoComplete="off"
        />
        <label htmlFor="key-expiry">Expires (optional)</label>
        <input
          id="key-expiry"
          type="datetime-local"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
        />
        <p className="muted">Leave blank for a key that never expires.</p>
        <label htmlFor="key-allowlist">IP allowlist (optional)</label>
        <input
          id="key-allowlist"
          type="text"
          value={allowlist}
          onChange={(e) => setAllowlist(e.target.value)}
          placeholder="e.g. 203.0.113.7, 10.0.0.0/8"
          autoComplete="off"
        />
        <p className="muted">
          Comma/space-separated IPs or CIDRs matched against the direct peer. Blank = any IP. Behind a
          reverse proxy the peer is the proxy, so prefer restricting at the proxy instead.
        </p>
        <label>Endpoint scope (optional)</label>
        {endpoints.length === 0 ? (
          <p className="muted">No endpoints yet — the key will allow all endpoints.</p>
        ) : (
          <div className="checks">
            {endpoints.map((e) => (
              <label key={e.name} className="check">
                <input
                  type="checkbox"
                  checked={scoped.includes(e.name)}
                  onChange={() => toggleScope(e.name)}
                />
                {e.name}
              </label>
            ))}
          </div>
        )}
        <button disabled={busy} onClick={doCreate}>
          {busy ? 'Creating…' : 'Create API key'}
        </button>

        {freshKey && (
          <>
            <p className="hint">
              Copy this key now — it is shown <strong>once</strong> and cannot be retrieved again.
            </p>
            <div className="codes">{freshKey}</div>
            <div className="row">
              <button className="ghost" onClick={() => copy(freshKey)}>
                Copy key
              </button>
              <button className="ghost" onClick={() => setFreshKey('')}>
                Done
              </button>
            </div>
          </>
        )}
      </div>

      <div className="section">
        <h2>API keys ({keys.length})</h2>
        {err && <p className="err">{err}</p>}
        {keys.length === 0 ? (
          <p className="muted">No API keys yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Key</th>
                <th>Scope</th>
                <th>Expires</th>
                <th>IP allowlist</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td>{k.label || '—'}</td>
                  <td className="mono">{k.key_masked}</td>
                  <td className="muted">
                    {k.endpoints.length === 0 ? 'all endpoints' : k.endpoints.join(', ')}
                  </td>
                  <td className="muted">{k.expires_at ? formatExpiry(k.expires_at) : 'never'}</td>
                  <td className="muted">
                    {k.ip_allowlist.length === 0 ? 'any IP' : k.ip_allowlist.join(', ')}
                  </td>
                  <td className="right">
                    <button className="ghost small" onClick={() => doRotate(k)}>
                      Rotate
                    </button>
                    <button className="danger small" onClick={() => doDelete(k)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

// formatExpiry renders an RFC3339 expiry compactly, flagging an already-expired key.
function formatExpiry(rfc3339: string): string {
  const d = new Date(rfc3339)
  if (isNaN(d.getTime())) return rfc3339
  const label = d.toLocaleString()
  return d.getTime() < Date.now() ? `${label} (expired)` : label
}
