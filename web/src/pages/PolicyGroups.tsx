import { useEffect, useState } from 'react'
import {
  createPolicyGroup,
  deletePolicyGroup,
  listAccounts,
  listPolicyGroups,
  STRATEGIES,
  type Account,
  type PolicyGroup,
} from '../api'
import { errMessage } from './ui'

export function PolicyGroups() {
  const [groups, setGroups] = useState<PolicyGroup[]>([])
  const [accounts, setAccounts] = useState<Account[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [strategy, setStrategy] = useState<string>(STRATEGIES[0])
  const [members, setMembers] = useState<string[]>([])

  async function load() {
    setErr('')
    try {
      const [g, a] = await Promise.all([listPolicyGroups(), listAccounts()])
      setGroups(g.policy_groups)
      setAccounts(a.accounts)
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  function toggleMember(id: string) {
    setMembers((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]))
  }

  async function doCreate() {
    setErr('')
    setBusy(true)
    try {
      await createPolicyGroup(name.trim(), strategy, members)
      setName('')
      setMembers([])
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function doDelete(g: PolicyGroup) {
    if (!confirm(`Delete policy group "${g.name}"?`)) return
    setErr('')
    try {
      await deletePolicyGroup(g.id)
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  const labelFor = (id: string) => accounts.find((a) => a.id === id)?.label || id

  return (
    <>
      <div className="section">
        <h2>New policy group</h2>
        <p className="muted">
          A named strategy over a chosen set of accounts. Bind it to an endpoint to route through it.
        </p>
        <label htmlFor="pg-name">Name</label>
        <input
          id="pg-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. balanced-pro"
          autoComplete="off"
        />
        <label htmlFor="pg-strategy">Strategy</label>
        <select id="pg-strategy" value={strategy} onChange={(e) => setStrategy(e.target.value)}>
          {STRATEGIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <label>Members</label>
        {accounts.length === 0 ? (
          <p className="muted">Import accounts first.</p>
        ) : (
          <div className="checks">
            {accounts.map((a) => (
              <label key={a.id} className="check">
                <input
                  type="checkbox"
                  checked={members.includes(a.id)}
                  onChange={() => toggleMember(a.id)}
                />
                {a.label || a.id}
              </label>
            ))}
          </div>
        )}
        <button disabled={busy || name.trim() === ''} onClick={doCreate}>
          {busy ? 'Creating…' : 'Create policy group'}
        </button>
      </div>

      <div className="section">
        <h2>Policy groups ({groups.length})</h2>
        {err && <p className="err">{err}</p>}
        {groups.length === 0 ? (
          <p className="muted">No policy groups yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Strategy</th>
                <th>Members</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.id}>
                  <td>{g.name}</td>
                  <td>
                    <span className="pill">{g.strategy}</span>
                  </td>
                  <td className="muted">
                    {g.member_account_ids.length === 0
                      ? '—'
                      : g.member_account_ids.map(labelFor).join(', ')}
                  </td>
                  <td className="right">
                    <button className="danger small" onClick={() => doDelete(g)}>
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
