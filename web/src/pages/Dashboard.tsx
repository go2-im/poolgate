import { useEffect, useState } from 'react'
import {
  getHealth,
  getStatus,
  getUsage,
  logout,
  type AccountHealth,
  type AccountUsage,
  type Me,
  type StatusSummary,
} from '../api'

// minHeadroom is the smallest remaining headroom across an account's usage
// windows (100 - used_percent), matching the best-quota metric. 100 when unknown.
function minHeadroom(u: AccountUsage | undefined): number {
  if (!u || u.windows.length === 0) return 100
  return Math.max(
    0,
    Math.min(...u.windows.map((w) => 100 - w.used_percent)),
  )
}

function stateClass(state: string): string {
  if (state === 'ok') return 'pill ok'
  if (state === 'unknown') return 'pill'
  if (state === 'revoked' || state === 'dead' || state === 'expired') return 'pill bad'
  return 'pill warn'
}

export function Dashboard({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [status, setStatus] = useState<StatusSummary | null>(null)
  const [usage, setUsage] = useState<AccountUsage[]>([])
  const [health, setHealth] = useState<AccountHealth[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    let live = true
    Promise.all([getStatus(), getUsage(), getHealth()])
      .then(([s, u, h]) => {
        if (!live) return
        setStatus(s)
        setUsage(u.usage)
        setHealth(h.health)
      })
      .catch((e) => live && setErr(e?.message ?? 'failed to load'))
    return () => {
      live = false
    }
  }, [])

  async function doLogout() {
    try {
      await logout()
    } finally {
      onLogout()
    }
  }

  const usageByID = new Map(usage.map((u) => [u.account_id, u]))

  return (
    <div className="app">
      <div className="topbar">
        <div>
          <span className="brand">poolgate</span>{' '}
          <span className="muted">· {me.operator}</span>
        </div>
        <button className="ghost" onClick={doLogout}>
          Sign out
        </button>
      </div>

      {err && <p className="err">{err}</p>}

      <div className="grid">
        <div className="tile">
          <div className="n">{status?.accounts ?? '—'}</div>
          <div className="k">Accounts</div>
        </div>
        <div className="tile">
          <div className="n">{status?.endpoints ?? '—'}</div>
          <div className="k">Endpoints</div>
        </div>
        <div className="tile">
          <div className="n">{status?.policy_groups ?? '—'}</div>
          <div className="k">Policy groups</div>
        </div>
        <div className="tile">
          <div className="n">{status?.schema_version ?? '—'}</div>
          <div className="k">Schema version</div>
        </div>
      </div>

      <div className="section">
        <h2>Accounts</h2>
        <p className="muted">Per-account state and remaining quota headroom.</p>
        {health.length === 0 ? (
          <p className="muted">No accounts imported yet — run <code>poolgate import &lt;auth.json&gt;</code>.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Account</th>
                <th>State</th>
                <th>Plan</th>
                <th>Min headroom</th>
              </tr>
            </thead>
            <tbody>
              {health.map((h) => {
                const u = usageByID.get(h.account_id)
                return (
                  <tr key={h.account_id}>
                    <td>{h.account_id}</td>
                    <td>
                      <span className={stateClass(h.state)}>{h.state}</span>
                    </td>
                    <td>{u?.plan_type || '—'}</td>
                    <td>{u ? `${minHeadroom(u).toFixed(0)}%` : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
