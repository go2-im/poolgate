import { useEffect, useMemo, useState } from 'react'
import {
  beginOAuthLogin,
  beginOAuthLoginManual,
  completeOAuthLoginManual,
  deleteAccount,
  importAccount,
  listAccounts,
  oauthLoginStatus,
  patchAccount,
  type Account,
} from '../api'
import { errMessage, stateClass } from './ui'

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

type SortKey = 'label' | 'state' | 'account_id' | 'created_at'

export function Accounts() {
  const [accounts, setAccounts] = useState<Account[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [content, setContent] = useState('')
  const [label, setLabel] = useState('')
  const [query, setQuery] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('label')
  const [sortDesc, setSortDesc] = useState(false)
  // Inline edit state (label + concurrency cap) for one row at a time.
  const [editId, setEditId] = useState('')
  const [editLabel, setEditLabel] = useState('')
  const [editCap, setEditCap] = useState('')
  // Interactive "sign in with ChatGPT" (OAuth) state.
  const [oauthLabel, setOauthLabel] = useState('')
  const [oauthBusy, setOauthBusy] = useState(false)
  const [oauthMsg, setOauthMsg] = useState('')
  // Headless (paste) flow state, for a browser not on the poolgate host.
  const [manualId, setManualId] = useState('')
  const [manualUrl, setManualUrl] = useState('')
  const [manualPaste, setManualPaste] = useState('')
  const [manualBusy, setManualBusy] = useState(false)
  const [manualMsg, setManualMsg] = useState('')

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

  // visible applies the case-insensitive search filter then the chosen sort. It
  // is memoized so typing/sorting doesn't re-run on unrelated renders.
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = q
      ? accounts.filter((a) =>
          [a.label, a.account_id, a.id, a.state].some((f) => f.toLowerCase().includes(q)),
        )
      : accounts
    const sorted = [...filtered].sort((a, b) => {
      const av = (a[sortKey] || '').toLowerCase()
      const bv = (b[sortKey] || '').toLowerCase()
      return av < bv ? -1 : av > bv ? 1 : 0
    })
    if (sortDesc) sorted.reverse()
    return sorted
  }, [accounts, query, sortKey, sortDesc])

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDesc((d) => !d)
    } else {
      setSortKey(key)
      setSortDesc(false)
    }
  }

  function sortArrow(key: SortKey): string {
    if (key !== sortKey) return ''
    return sortDesc ? ' ▼' : ' ▲'
  }

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

  // doOAuthLogin starts the interactive browser sign-in, opens the authorize URL
  // in a new tab, then polls until the loopback callback completes. Only works
  // when this browser is on the poolgate host (the callback lands on 127.0.0.1).
  async function doOAuthLogin() {
    setErr('')
    setOauthBusy(true)
    setOauthMsg('Starting sign-in…')
    try {
      const { login_id, authorize_url } = await beginOAuthLogin(oauthLabel.trim())
      window.open(authorize_url, '_blank', 'noopener,noreferrer')
      setOauthMsg('A sign-in tab was opened — complete it there. Waiting…')
      const deadline = Date.now() + 5 * 60 * 1000
      while (Date.now() < deadline) {
        await sleep(1500)
        const st = await oauthLoginStatus(login_id)
        if (st.status === 'success') {
          setOauthMsg('')
          setOauthLabel('')
          await load()
          return
        }
        if (st.status === 'error') {
          setErr(st.error)
          setOauthMsg('')
          return
        }
      }
      setErr('sign-in timed out')
      setOauthMsg('')
    } catch (e) {
      setErr(errMessage(e))
      setOauthMsg('')
    } finally {
      setOauthBusy(false)
    }
  }

  // doManualBegin starts the headless flow: it fetches an authorize URL and opens
  // it, then the operator pastes back the redirect URL to complete.
  async function doManualBegin() {
    setErr('')
    setManualBusy(true)
    setManualMsg('')
    try {
      const { login_id, authorize_url } = await beginOAuthLoginManual(oauthLabel.trim())
      setManualId(login_id)
      setManualUrl(authorize_url)
      window.open(authorize_url, '_blank', 'noopener,noreferrer')
      setManualMsg('Signed in? Paste the redirected URL below.')
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setManualBusy(false)
    }
  }

  async function doManualComplete() {
    setErr('')
    setManualBusy(true)
    try {
      await completeOAuthLoginManual(manualId, manualPaste.trim())
      setManualId('')
      setManualUrl('')
      setManualPaste('')
      setManualMsg('')
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setManualBusy(false)
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

  function startEdit(a: Account) {
    setEditId(a.id)
    setEditLabel(a.label)
    setEditCap(String(a.concurrency_cap))
  }

  function cancelEdit() {
    setEditId('')
  }

  async function saveEdit(id: string) {
    const cap = parseInt(editCap, 10)
    if (isNaN(cap) || cap < 0) {
      setErr('Concurrency cap must be a non-negative integer (0 = unlimited).')
      return
    }
    setErr('')
    try {
      await patchAccount(id, { label: editLabel.trim(), concurrency_cap: cap })
      setEditId('')
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

        <div className="divider">or</div>

        <h3>Sign in with ChatGPT</h3>
        <p className="muted">
          Add an account by signing in through the browser (OAuth) instead of pasting a{' '}
          <code>auth.json</code>.
        </p>
        <label htmlFor="oauth-label">Label (optional)</label>
        <input
          id="oauth-label"
          type="text"
          value={oauthLabel}
          onChange={(e) => setOauthLabel(e.target.value)}
          placeholder="e.g. pro-account-2"
          autoComplete="off"
          disabled={oauthBusy || manualBusy}
        />

        <h4>On this machine</h4>
        <p className="muted">
          Use this when the browser is on the poolgate host. It opens a sign-in tab and completes
          automatically on a loopback callback.
        </p>
        <button disabled={oauthBusy || manualBusy} onClick={doOAuthLogin}>
          {oauthBusy ? 'Signing in…' : 'Sign in with ChatGPT'}
        </button>
        {oauthMsg && <p className="hint">{oauthMsg}</p>}

        <h4>On another machine (remote)</h4>
        <p className="muted">
          Use this over a reverse proxy / SSH when the browser is not on the poolgate host. After
          you sign in, the browser is sent to a <code>http://localhost:1455/…</code> page that
          won&rsquo;t load — copy that full address from the address bar and paste it below.
        </p>
        {!manualUrl ? (
          <button disabled={oauthBusy || manualBusy} onClick={doManualBegin}>
            {manualBusy ? 'Starting…' : 'Get sign-in link'}
          </button>
        ) : (
          <>
            <p className="hint">
              A sign-in tab was opened. If it didn&rsquo;t,{' '}
              <a href={manualUrl} target="_blank" rel="noopener noreferrer">
                use this link
              </a>
              .
            </p>
            <label htmlFor="oauth-paste">Redirected URL</label>
            <textarea
              id="oauth-paste"
              className="mono"
              rows={3}
              value={manualPaste}
              onChange={(e) => setManualPaste(e.target.value)}
              placeholder="http://localhost:1455/auth/callback?code=…&state=…"
            />
            <button disabled={manualBusy || manualPaste.trim() === ''} onClick={doManualComplete}>
              {manualBusy ? 'Completing…' : 'Complete sign-in'}
            </button>
          </>
        )}
        {manualMsg && <p className="hint">{manualMsg}</p>}
      </div>

      <div className="section">
        <h2>Pool ({accounts.length})</h2>
        {err && <p className="err">{err}</p>}
        {accounts.length === 0 ? (
          <p className="muted">No accounts yet.</p>
        ) : (
          <>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search label, ChatGPT account, id, or state…"
              autoComplete="off"
              aria-label="Search accounts"
            />
            {visible.length === 0 ? (
              <p className="muted">No accounts match “{query}”.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th className="sortable" onClick={() => toggleSort('label')}>
                      Label{sortArrow('label')}
                    </th>
                    <th className="sortable" onClick={() => toggleSort('account_id')}>
                      ChatGPT account{sortArrow('account_id')}
                    </th>
                    <th className="sortable" onClick={() => toggleSort('state')}>
                      State{sortArrow('state')}
                    </th>
                    <th>Concurrency cap</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((a) =>
                    editId === a.id ? (
                      <tr key={a.id}>
                        <td className="mono">{a.id}</td>
                        <td>
                          <input
                            type="text"
                            value={editLabel}
                            onChange={(e) => setEditLabel(e.target.value)}
                            aria-label="Label"
                          />
                        </td>
                        <td className="mono">{a.account_id || '—'}</td>
                        <td>
                          <span className={stateClass(a.state)}>{a.state}</span>
                        </td>
                        <td>
                          <input
                            type="number"
                            min={0}
                            value={editCap}
                            onChange={(e) => setEditCap(e.target.value)}
                            aria-label="Concurrency cap (0 = unlimited)"
                          />
                        </td>
                        <td className="right">
                          <button className="small" onClick={() => saveEdit(a.id)}>
                            Save
                          </button>{' '}
                          <button className="ghost small" onClick={cancelEdit}>
                            Cancel
                          </button>
                        </td>
                      </tr>
                    ) : (
                      <tr key={a.id}>
                        <td className="mono">{a.id}</td>
                        <td>{a.label || '—'}</td>
                        <td className="mono">{a.account_id || '—'}</td>
                        <td>
                          <span className={stateClass(a.state)}>{a.state}</span>
                        </td>
                        <td>{a.concurrency_cap === 0 ? 'unlimited' : a.concurrency_cap}</td>
                        <td className="right">
                          <button className="ghost small" onClick={() => startEdit(a)}>
                            Edit
                          </button>{' '}
                          <button className="danger small" onClick={() => doDelete(a.id)}>
                            Delete
                          </button>
                        </td>
                      </tr>
                    ),
                  )}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>
    </>
  )
}
