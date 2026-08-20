import { useEffect, useState } from 'react'
import {
  getHealth,
  getStatus,
  getUsage,
  type AccountHealth,
  type AccountUsage,
  type StatusSummary,
} from '../api'
import { stateClass } from './ui'

// minHeadroom is the smallest remaining headroom across an account's usage
// windows (100 - used_percent), matching the best-quota metric. 100 when unknown.
function minHeadroom(u: AccountUsage | undefined): number {
  if (!u || u.windows.length === 0) return 100
  return Math.max(0, Math.min(...u.windows.map((w) => 100 - w.used_percent)))
}

export function Dashboard() {
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

  const usageByID = new Map(usage.map((u) => [u.account_id, u]))
  const healthyCount = health.filter((account) => account.state === 'ok').length
  const degradedCount = health.length - healthyCount
  const knownHeadroom = health
    .map((account) => usageByID.get(account.account_id))
    .filter((accountUsage): accountUsage is AccountUsage => accountUsage !== undefined)
    .map(minHeadroom)
  const poolHeadroom = knownHeadroom.length > 0 ? Math.min(...knownHeadroom) : null
  const bannerState =
    status === null ? 'loading' : health.length === 0 ? 'empty' : degradedCount === 0 ? 'ready' : 'warn'
  const bannerClass = bannerState === 'warn' ? 'health-banner warn' : bannerState === 'ready' ? 'health-banner' : 'health-banner neutral'

  return (
    <>
      {err && <p className="err notice">{err}</p>}

      <div className={bannerClass}>
        <span className="health-beacon" />
        <strong>
          {bannerState === 'loading'
            ? 'Loading pool status…'
            : bannerState === 'empty'
              ? 'Add an account to start routing'
              : bannerState === 'ready'
                ? 'Pool is ready for traffic'
                : 'Pool is operating with reduced capacity'}
        </strong>
        <span>
          {bannerState === 'loading'
            ? 'Checking account health and routing readiness.'
            : health.length === 0
            ? 'Account health will appear after the first account is imported.'
            : `${healthyCount} of ${health.length} accounts are currently eligible for routing.`}
        </span>
      </div>

      <div className="grid metric-grid">
        <div className="tile">
          <div className="k">Accounts</div>
          <div className="n">{status?.accounts ?? '—'}</div>
          <div className="tile-meta">{healthyCount} healthy</div>
        </div>
        <div className="tile">
          <div className="k">Endpoints</div>
          <div className="n">{status?.endpoints ?? '—'}</div>
          <div className="tile-meta">Client-facing routes</div>
        </div>
        <div className="tile">
          <div className="k">Routing policies</div>
          <div className="n">{status?.policy_groups ?? '—'}</div>
          <div className="tile-meta">Reusable account groups</div>
        </div>
        <div className="tile">
          <div className="k">Pool headroom</div>
          <div className="n">{poolHeadroom === null ? '—' : `${poolHeadroom.toFixed(0)}%`}</div>
          <div className="tile-meta">Lowest known window</div>
        </div>
      </div>

      <div className="section dashboard-accounts">
        <div className="section-heading">
          <div>
            <h2>Account health</h2>
            <p className="muted">State, plan, and remaining quota headroom for every pooled account.</p>
          </div>
          <span className="schema-badge">schema {status?.schema_version ?? '—'}</span>
        </div>
        {health.length === 0 ? (
          <div className="empty-state">
            <strong>No accounts imported yet</strong>
            <span>
              Run <code>poolgate import &lt;auth.json&gt;</code> or add one from the Accounts page.
            </span>
          </div>
        ) : (
          <div className="table-scroll">
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
                {health.map((account) => {
                  const accountUsage = usageByID.get(account.account_id)
                  const headroom = accountUsage ? minHeadroom(accountUsage) : null
                  return (
                    <tr key={account.account_id}>
                      <td>
                        <span className="account-name">
                          <span className="account-avatar">{account.account_id.slice(0, 2).toUpperCase()}</span>
                          <span className="mono">{account.account_id}</span>
                        </span>
                      </td>
                      <td>
                        <span className={stateClass(account.state)}>{account.state}</span>
                      </td>
                      <td>{accountUsage?.plan_type || '—'}</td>
                      <td>
                        {headroom === null ? (
                          '—'
                        ) : (
                          <span className="headroom-cell">
                            <progress max="100" value={headroom} />
                            <span>{headroom.toFixed(0)}%</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
