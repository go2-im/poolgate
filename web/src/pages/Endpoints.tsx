import { useEffect, useMemo, useState } from 'react'
import {
  createEndpoint,
  deleteEndpoint,
  getSettings,
  listEndpoints,
  listPolicyGroups,
  type Endpoint,
  type PolicyGroup,
} from '../api'
import { copy, errMessage } from './ui'

export function Endpoints() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  const [groups, setGroups] = useState<PolicyGroup[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [groupID, setGroupID] = useState('')
  // Client-config generator state. base is seeded from the server's proxy_base
  // hint but stays editable (operators fronting poolgate use their own hostname).
  const [base, setBase] = useState('')
  const [cfgEndpoint, setCfgEndpoint] = useState('')
  const [cfgKey, setCfgKey] = useState('')

  async function load() {
    setErr('')
    try {
      const [e, g, s] = await Promise.all([listEndpoints(), listPolicyGroups(), getSettings()])
      setEndpoints(e.endpoints)
      setGroups(g.policy_groups)
      if (!groupID && g.policy_groups.length > 0) setGroupID(g.policy_groups[0].id)
      setBase((b) => b || s.proxy_base || '')
      setCfgEndpoint((c) => c || e.endpoints[0]?.name || '')
    } catch (ex) {
      setErr(errMessage(ex))
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function doCreate() {
    setErr('')
    setBusy(true)
    try {
      await createEndpoint(name.trim(), groupID)
      setName('')
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function doDelete(n: string) {
    if (!confirm(`Delete endpoint "${n}"?`)) return
    setErr('')
    try {
      await deleteEndpoint(n)
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  const groupName = (id: string) => groups.find((g) => g.id === id)?.name || id
  const trimmedBase = base.replace(/\/+$/, '')
  const endpointURL = (n: string) => `${trimmedBase}/e/${n}/v1`

  // The generated client config: a curl invocation plus the OpenAI-compatible
  // env vars, for the chosen endpoint + key. The key stays client-side (it is
  // never sent anywhere by this page).
  const snippet = useMemo(() => {
    const url = endpointURL(cfgEndpoint || '<endpoint>')
    const key = cfgKey.trim() || 'sk-...your-key...'
    return [
      `# OpenAI-compatible base URL + key`,
      `export OPENAI_BASE_URL="${url}"`,
      `export OPENAI_API_KEY="${key}"`,
      ``,
      `# Example request (streaming responses):`,
      `curl -N "${url}/responses" \\`,
      `  -H "Authorization: Bearer ${key}" \\`,
      `  -H "Content-Type: application/json" \\`,
      `  -d '{"model":"gpt-5","input":"hello"}'`,
    ].join('\n')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trimmedBase, cfgEndpoint, cfgKey])

  return (
    <>
      <div className="section">
        <h2>New endpoint</h2>
        <p className="muted">
          A named inbound route bound to one policy group, surfaced at{' '}
          <code>/e/&lt;name&gt;/v1</code>. Callers pick a strategy by choosing the URL.
        </p>
        <label htmlFor="ep-name">Name</label>
        <input
          id="ep-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. prod"
          autoComplete="off"
        />
        <label htmlFor="ep-group">Policy group</label>
        {groups.length === 0 ? (
          <p className="muted">Create a policy group first.</p>
        ) : (
          <select id="ep-group" value={groupID} onChange={(e) => setGroupID(e.target.value)}>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} ({g.strategy})
              </option>
            ))}
          </select>
        )}
        <button disabled={busy || name.trim() === '' || groupID === ''} onClick={doCreate}>
          {busy ? 'Creating…' : 'Create endpoint'}
        </button>
      </div>

      <div className="section">
        <h2>Endpoints ({endpoints.length})</h2>
        {err && <p className="err">{err}</p>}
        {endpoints.length === 0 ? (
          <p className="muted">No endpoints yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Policy group</th>
                <th>Client base URL</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr key={e.name}>
                  <td>{e.name}</td>
                  <td>{groupName(e.group_id)}</td>
                  <td className="mono">{endpointURL(e.name)}</td>
                  <td className="right">
                    <button className="ghost small" onClick={() => copy(endpointURL(e.name))}>
                      Copy
                    </button>{' '}
                    <button className="danger small" onClick={() => doDelete(e.name)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {endpoints.length > 0 && (
        <div className="section">
          <h2>Client configuration</h2>
          <p className="muted">
            Generate a copy-paste config to point an OpenAI-compatible client (Codex, Cursor, the
            OpenAI SDK) at an endpoint. The base URL is seeded from the proxy listener — edit it to
            your external hostname when poolgate is fronted by a reverse proxy. The key is used only
            to build the snippet here; it is not sent anywhere.
          </p>
          <label htmlFor="cfg-base">Base URL</label>
          <input
            id="cfg-base"
            type="text"
            value={base}
            onChange={(e) => setBase(e.target.value)}
            placeholder="https://api.example.com"
            autoComplete="off"
          />
          <label htmlFor="cfg-endpoint">Endpoint</label>
          <select id="cfg-endpoint" value={cfgEndpoint} onChange={(e) => setCfgEndpoint(e.target.value)}>
            {endpoints.map((e) => (
              <option key={e.name} value={e.name}>
                {e.name}
              </option>
            ))}
          </select>
          <label htmlFor="cfg-key">API key (optional)</label>
          <input
            id="cfg-key"
            type="text"
            value={cfgKey}
            onChange={(e) => setCfgKey(e.target.value)}
            placeholder="sk-… (paste one from API keys)"
            autoComplete="off"
          />
          <pre className="codes">{snippet}</pre>
          <button className="ghost" onClick={() => copy(snippet)}>
            Copy config
          </button>
        </div>
      )}
    </>
  )
}
