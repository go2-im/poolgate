import { useCallback, useEffect, useRef, useState } from 'react'
import {
  getMonitorCounters,
  listRequestLogs,
  monitorStreamURL,
  type MonitorFilter,
  type RequestCounters,
  type RequestLog,
} from '../api'
import { errMessage } from './ui'

// MAX_ROWS caps the in-memory log list so a long-lived live session cannot grow
// unbounded; the newest rows are kept.
const MAX_ROWS = 300

const EMPTY_COUNTERS: RequestCounters = { total: 0, success: 0, error: 0, tokens_in: 0, tokens_out: 0 }

// statusPill maps an HTTP status to a pill class (0 = transport failure = bad).
function statusPill(status: number): string {
  if (status >= 200 && status < 300) return 'pill ok'
  if (status === 0) return 'pill bad'
  if (status >= 500 || status === 429) return 'pill warn'
  return 'pill bad'
}

// hhmmss renders just the wall-clock time of an ISO timestamp (dates clutter a
// live tail); falls back to the raw value if unparseable.
function hhmmss(iso: string): string {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleTimeString()
}

type ConnState = 'live' | 'paused' | 'connecting' | 'error'

export function Monitor() {
  const [draft, setDraft] = useState<MonitorFilter>({})
  const [applied, setApplied] = useState<MonitorFilter>({})
  const [logs, setLogs] = useState<RequestLog[]>([])
  const [counters, setCounters] = useState<RequestCounters>(EMPTY_COUNTERS)
  const [err, setErr] = useState('')
  const [live, setLive] = useState(true)
  const [conn, setConn] = useState<ConnState>('paused')
  const esRef = useRef<EventSource | null>(null)

  // load fetches the history + counters for the applied filter (the SSE stream
  // then layers live rows on top).
  const load = useCallback(async () => {
    setErr('')
    try {
      const [l, c] = await Promise.all([
        listRequestLogs({ ...applied, limit: MAX_ROWS }),
        getMonitorCounters(applied),
      ])
      setLogs(l.logs)
      setCounters(c)
    } catch (e) {
      setErr(errMessage(e))
    }
  }, [applied])

  useEffect(() => {
    void load()
  }, [load])

  // Live SSE: (re)open the stream whenever the applied filter changes or live is
  // toggled on; always close the previous EventSource first, and on cleanup.
  useEffect(() => {
    esRef.current?.close()
    esRef.current = null
    if (!live) {
      setConn('paused')
      return
    }
    setConn('connecting')
    const es = new EventSource(monitorStreamURL(applied))
    esRef.current = es
    es.onopen = () => setConn('live')
    es.onerror = () => setConn('error') // EventSource auto-retries in the background
    es.onmessage = (ev) => {
      let rec: RequestLog
      try {
        rec = JSON.parse(ev.data)
      } catch {
        return
      }
      setLogs((cur) => [rec, ...cur].slice(0, MAX_ROWS))
      // Keep counters live by folding the new record in (server-side counters
      // agree on next manual reload).
      setCounters((c) => ({
        total: c.total + 1,
        success: c.success + (rec.status >= 200 && rec.status < 300 ? 1 : 0),
        error: c.error + (rec.status >= 200 && rec.status < 300 ? 0 : 1),
        tokens_in: c.tokens_in + (rec.tokens_in || 0),
        tokens_out: c.tokens_out + (rec.tokens_out || 0),
      }))
    }
    return () => {
      es.close()
      if (esRef.current === es) esRef.current = null
    }
  }, [applied, live])

  function apply() {
    // Trim blanks so the query omits empty facets; a new object identity triggers
    // both the history reload and the SSE reconnect.
    const f: MonitorFilter = {}
    if (draft.session?.trim()) f.session = draft.session.trim()
    if (draft.api_key?.trim()) f.api_key = draft.api_key.trim()
    if (draft.model?.trim()) f.model = draft.model.trim()
    if (draft.endpoint?.trim()) f.endpoint = draft.endpoint.trim()
    if (draft.account?.trim()) f.account = draft.account.trim()
    if (draft.status?.trim()) f.status = draft.status.trim()
    setApplied(f)
  }

  function clear() {
    setDraft({})
    setApplied({})
  }

  const connLabel: Record<ConnState, string> = {
    live: 'live',
    paused: 'paused',
    connecting: 'connecting…',
    error: 'reconnecting…',
  }
  const connClass: Record<ConnState, string> = {
    live: 'pill ok',
    paused: 'pill',
    connecting: 'pill warn',
    error: 'pill bad',
  }

  function set(k: keyof MonitorFilter, v: string) {
    setDraft((d) => ({ ...d, [k]: v }))
  }

  return (
    <>
      <div className="grid">
        <div className="tile">
          <div className="n">{counters.total}</div>
          <div className="k">Requests</div>
        </div>
        <div className="tile">
          <div className="n">{counters.success}</div>
          <div className="k">Success (2xx)</div>
        </div>
        <div className="tile">
          <div className="n">{counters.error}</div>
          <div className="k">Errors</div>
        </div>
        <div className="tile">
          <div className="n">{counters.tokens_in + counters.tokens_out}</div>
          <div className="k">Tokens (in+out)</div>
        </div>
      </div>

      <div className="section">
        <div className="topbar">
          <h2>Live requests</h2>
          <span className={connClass[conn]}>{connLabel[conn]}</span>
        </div>

        <div className="filters">
          <input
            type="text"
            value={draft.session ?? ''}
            onChange={(e) => set('session', e.target.value)}
            placeholder="session id"
            autoComplete="off"
          />
          <input
            type="text"
            value={draft.api_key ?? ''}
            onChange={(e) => set('api_key', e.target.value)}
            placeholder="api key id"
            autoComplete="off"
          />
          <input
            type="text"
            value={draft.model ?? ''}
            onChange={(e) => set('model', e.target.value)}
            placeholder="model"
            autoComplete="off"
          />
          <input
            type="text"
            value={draft.endpoint ?? ''}
            onChange={(e) => set('endpoint', e.target.value)}
            placeholder="endpoint"
            autoComplete="off"
          />
          <input
            type="text"
            value={draft.account ?? ''}
            onChange={(e) => set('account', e.target.value)}
            placeholder="account id"
            autoComplete="off"
          />
          <input
            type="text"
            value={draft.status ?? ''}
            onChange={(e) => set('status', e.target.value)}
            placeholder="status"
            inputMode="numeric"
            autoComplete="off"
          />
        </div>
        <div className="row">
          <button className="small" onClick={apply}>
            Apply
          </button>
          <button className="ghost small" onClick={clear}>
            Clear
          </button>
          <button className="ghost small" onClick={() => setLive((v) => !v)}>
            {live ? 'Pause' : 'Resume'} live
          </button>
          <button className="ghost small" onClick={() => void load()}>
            Refresh
          </button>
        </div>

        {err && <p className="err">{err}</p>}
        {logs.length === 0 ? (
          <p className="muted">No requests recorded yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Endpoint</th>
                <th>Account</th>
                <th>Model</th>
                <th>Status</th>
                <th className="right">ms</th>
                <th className="right">tok in/out</th>
                <th>Trace</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id}>
                  <td className="mono">{hhmmss(l.at)}</td>
                  <td>{l.endpoint || '—'}</td>
                  <td>{l.account_label || l.account_id || '—'}</td>
                  <td className="mono">{l.model || '—'}</td>
                  <td>
                    <span className={statusPill(l.status)}>{l.status || 'fail'}</span>
                    {l.error_type && <span className="muted"> {l.error_type}</span>}
                  </td>
                  <td className="right">{l.latency_ms}</td>
                  <td className="right mono">
                    {l.tokens_in}/{l.tokens_out}
                  </td>
                  <td className="mono muted trace">{l.trace || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
