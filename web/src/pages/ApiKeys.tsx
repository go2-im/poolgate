import { useEffect, useState } from 'react'
import {
  createApiKey,
  deleteApiKey,
  listApiKeys,
  listEndpoints,
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

  async function doCreate() {
    setErr('')
    setBusy(true)
    try {
      const created = await createApiKey(label.trim(), scoped)
      setFreshKey(created.key ?? '')
      setLabel('')
      setScoped([])
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
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
                  <td className="right">
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
