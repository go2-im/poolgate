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

// COUNTER_DEBOUNCE_MS bounds how often live activity triggers a counters refetch.
// Counters are always the server's authoritative aggregate — never folded on the
// client — so they can never drift/double-count; they just lag live activity by
// at most this window.
const COUNTER_DEBOUNCE_MS = 4000

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

// mergeLogs unions two log lists, deduped by id and ordered newest-first, capped
// at MAX_ROWS. Used so a completing history load() cannot drop live rows that
// arrived during the fetch window, and so a record present in both the history
// snapshot and the live stream is never rendered twice.
function mergeLogs(a: RequestLog[], b: RequestLog[]): RequestLog[] {
  const seen = new Set<string>()
  const out: RequestLog[] = []
  for (const l of [...a, ...b]) {
    if (seen.has(l.id)) continue
    seen.add(l.id)
    out.push(l)
  }
  out.sort((x, y) => (x.at < y.at ? 1 : x.at > y.at ? -1 : 0))
  return out.slice(0, MAX_ROWS)
}

type ConnState = 'live' | 'paused' | 'connecting' | 'error' | 'failed'

export function Monitor() {
  const [draft, setDraft] = useState<MonitorFilter>({})
  const [applied, setApplied] = useState<MonitorFilter>({})
  const [logs, setLogs] = useState<RequestLog[]>([])
  const [counters, setCounters] = useState<RequestCounters>(EMPTY_COUNTERS)
  const [err, setErr] = useState('')
  const [live, setLive] = useState(true)
  const [conn, setConn] = useState<ConnState>('paused')
  const esRef = useRef<EventSource | null>(null)
  // ctTimer debounces counter refetches triggered by live activity.
  const ctTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // seenRef tracks the ids already in the log list so onmessage can dedup without
  // rescanning the whole array on every event; reset whenever the filter changes.
  const seenRef = useRef<Set<string>>(new Set())

  // refreshCounters fetches the server-authoritative aggregate for a filter. It
  // ignores stale in-flight responses via the applied identity captured by the
  // caller (see the effect below).
  const refreshCounters = useCallback(async (f: MonitorFilter) => {
    try {
      const c = await getMonitorCounters(f)
      setCounters(c)
    } catch {
      // A transient counters error should not clobber the live tail; leave the
      // last-known counts in place.
    }
  }, [])

  // load fetches the history + counters for the applied filter and MERGES the
  // history into whatever the live stream has already delivered (so a record
  // streamed during the fetch window is preserved, and a record present in both
  // is not duplicated). Counters come straight from the server.
  const load = useCallback(async () => {
    setErr('')
    try {
      const [l, c] = await Promise.all([
        listRequestLogs({ ...applied, limit: MAX_ROWS }),
        getMonitorCounters(applied),
      ])
      setLogs((cur) => {
        const merged = mergeLogs(cur, l.logs)
        seenRef.current = new Set(merged.map((x) => x.id))
        return merged
      })
      setCounters(c)
    } catch (e) {
      setErr(errMessage(e))
    }
  }, [applied])

  // On a filter change, clear the tail + seen set so rows from the previous filter
  // never linger, then load fresh history.
  useEffect(() => {
    setLogs([])
    seenRef.current = new Set()
    void load()
  }, [applied, load])

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
    es.onerror = () => {
      // Per the SSE spec, EventSource only auto-retries a connection that had
      // opened and then dropped (readyState CONNECTING). A non-2xx initial
      // response (e.g. 503 when the monitor is not wired) CLOSES the connection
      // permanently — surface that as a distinct "failed" state rather than a
      // misleading "reconnecting…".
      setConn(es.readyState === EventSource.CLOSED ? 'failed' : 'error')
    }
    es.onmessage = (ev) => {
      let rec: RequestLog
      try {
        rec = JSON.parse(ev.data)
      } catch {
        return
      }
      if (seenRef.current.has(rec.id)) return // dedup: already shown (history or a prior frame)
      seenRef.current.add(rec.id)
      setLogs((cur) => mergeLogs([rec], cur))
      // Counters stay server-authoritative: schedule a debounced refetch instead
      // of folding the record in (which could double-count against the aggregate
      // or be lost when a history load resolves).
      if (ctTimer.current === null) {
        ctTimer.current = setTimeout(() => {
          ctTimer.current = null
          void refreshCounters(applied)
        }, COUNTER_DEBOUNCE_MS)
      }
    }
    return () => {
      es.close()
      if (esRef.current === es) esRef.current = null
    }
  }, [applied, live, refreshCounters])

  // Clear any pending counter-refresh timer on unmount.
  useEffect(() => {
    return () => {
      if (ctTimer.current !== null) {
        clearTimeout(ctTimer.current)
        ctTimer.current = null
      }
    }
  }, [])

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
    failed: 'disconnected — resume to retry',
  }
  const connClass: Record<ConnState, string> = {
    live: 'pill ok',
    paused: 'pill',
    connecting: 'pill warn',
    error: 'pill warn',
    failed: 'pill bad',
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
