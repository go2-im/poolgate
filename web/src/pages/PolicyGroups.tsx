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
  const [weights, setWeights] = useState<Record<string, string>>({})

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

  // collectWeights builds the member_weights map (accountID → int >=1) from the
  // per-member inputs, only for selected members with a non-default value.
  function collectWeights(): Record<string, number> | undefined {
    if (strategy !== 'weighted') return undefined
    const out: Record<string, number> = {}
    for (const id of members) {
      const n = parseInt(weights[id] ?? '', 10)
      if (!isNaN(n) && n > 1) out[id] = n
    }
    return Object.keys(out).length > 0 ? out : undefined
  }

  async function doCreate() {
    setErr('')
    setBusy(true)
    try {
      await createPolicyGroup(name.trim(), strategy, members, collectWeights())
      setName('')
      setMembers([])
      setWeights({})
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
                {strategy === 'weighted' && members.includes(a.id) && (
                  <input
                    type="number"
                    min={1}
                    className="weight-input"
                    value={weights[a.id] ?? ''}
                    placeholder="wt 1"
                    aria-label={`weight for ${a.label || a.id}`}
                    onChange={(e) => setWeights((w) => ({ ...w, [a.id]: e.target.value }))}
                  />
                )}
              </label>
            ))}
          </div>
        )}
        {strategy === 'weighted' && (
          <p className="muted">Weights (≥1, default 1) set each member's share of traffic.</p>
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
                      : g.member_account_ids
                          .map((id) => {
                            const w = g.member_weights?.[id]
                            return w && w > 1 ? `${labelFor(id)} ×${w}` : labelFor(id)
                          })
                          .join(', ')}
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
