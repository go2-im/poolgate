import { useEffect, useState } from 'react'
import {
  createEndpoint,
  deleteEndpoint,
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

  async function load() {
    setErr('')
    try {
      const [e, g] = await Promise.all([listEndpoints(), listPolicyGroups()])
      setEndpoints(e.endpoints)
      setGroups(g.policy_groups)
      if (!groupID && g.policy_groups.length > 0) setGroupID(g.policy_groups[0].id)
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
  // The proxy listens on its own port (default 8787), separate from this admin
  // origin — show a copyable base URL with the host to fill in.
  const proxyURL = (n: string) => `http://<proxy-host>:8787/e/${n}/v1`

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
                  <td className="mono">{proxyURL(e.name)}</td>
                  <td className="right">
                    <button className="ghost small" onClick={() => copy(proxyURL(e.name))}>
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
    </>
  )
}
