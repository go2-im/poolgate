import { useEffect, useState } from 'react'
import { deleteAccount, importAccount, listAccounts, type Account } from '../api'
import { errMessage, stateClass } from './ui'

export function Accounts() {
  const [accounts, setAccounts] = useState<Account[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [content, setContent] = useState('')
  const [label, setLabel] = useState('')

  async function load() {
    setErr('')
    try {
      const r = await listAccounts()
      setAccounts(r.accounts)
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  async function doImport() {
    setErr('')
    setBusy(true)
    try {
      await importAccount(content.trim(), label.trim())
      setContent('')
      setLabel('')
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function doDelete(id: string) {
    if (!confirm(`Delete account ${id}? This cannot be undone.`)) return
    setErr('')
    try {
      await deleteAccount(id)
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  return (
    <>
      <div className="section">
        <h2>Import account</h2>
        <p className="muted">
          Paste the contents of a Codex <code>auth.json</code>. Import is always explicit — accounts
          are never picked up automatically.
        </p>
        <label htmlFor="acc-label">Label (optional)</label>
        <input
          id="acc-label"
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. pro-account-1"
          autoComplete="off"
        />
        <label htmlFor="acc-content">auth.json</label>
        <textarea
          id="acc-content"
          className="mono"
          rows={5}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder='{"OPENAI_API_KEY":null,"tokens":{...}}'
        />
        <button disabled={busy || content.trim() === ''} onClick={doImport}>
          {busy ? 'Importing…' : 'Import account'}
        </button>
      </div>

      <div className="section">
        <h2>Pool ({accounts.length})</h2>
        {err && <p className="err">{err}</p>}
        {accounts.length === 0 ? (
          <p className="muted">No accounts yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Label</th>
                <th>ChatGPT account</th>
                <th>State</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.id}</td>
                  <td>{a.label || '—'}</td>
                  <td className="mono">{a.account_id || '—'}</td>
                  <td>
                    <span className={stateClass(a.state)}>{a.state}</span>
                  </td>
                  <td className="right">
                    <button className="danger small" onClick={() => doDelete(a.id)}>
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
