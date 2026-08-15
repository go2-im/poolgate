import { useEffect, useState } from 'react'
import {
  CHANNEL_TYPES,
  EVENT_KINDS,
  createNotifyChannel,
  deleteNotifyChannel,
  listNotifyChannels,
  setNotifyChannelEnabled,
  testNotifyChannel,
  type NotifyChannel,
  type NotifyChannelType,
  type NotifyEventKind,
} from '../api'
import { errMessage } from './ui'

// A human label for each event kind, so the checkbox list reads clearly.
const EVENT_LABELS: Record<NotifyEventKind, string> = {
  account_expired: 'Account expired',
  account_cooldown: 'Account cooldown',
  account_quota_exhausted: 'Quota exhausted',
  account_recovered: 'Account recovered',
  quota_low: 'Quota low',
  policy_no_healthy_member: 'Policy: no healthy member',
  auth_anomaly: 'Auth anomaly',
  startup_bind_warning: 'Startup bind warning',
}

export function Notifications() {
  const [channels, setChannels] = useState<NotifyChannel[]>([])
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  // create form
  const [type, setType] = useState<NotifyChannelType>('dingtalk')
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [method, setMethod] = useState('POST')
  const [template, setTemplate] = useState('')
  const [events, setEvents] = useState<NotifyEventKind[]>([])
  const [minHeadroom, setMinHeadroom] = useState('')
  const [dedup, setDedup] = useState('')

  async function load() {
    setErr('')
    try {
      const r = await listNotifyChannels()
      setChannels(r.channels)
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  function toggleEvent(k: NotifyEventKind) {
    setEvents((s) => (s.includes(k) ? s.filter((x) => x !== k) : [...s, k]))
  }

  function resetForm() {
    setName('')
    setUrl('')
    setSecret('')
    setMethod('POST')
    setTemplate('')
    setEvents([])
    setMinHeadroom('')
    setDedup('')
  }

  async function doCreate() {
    setErr('')
    setNote('')
    setBusy(true)
    try {
      await createNotifyChannel({
        type,
        name: name.trim(),
        events,
        min_headroom: minHeadroom ? Number(minHeadroom) : 0,
        dedup_seconds: dedup ? Number(dedup) : 0,
        config: {
          url: url.trim(),
          secret: secret.trim() || undefined,
          method: type === 'webhook' ? method.trim() || undefined : undefined,
          template: type === 'webhook' ? template.trim() || undefined : undefined,
        },
      })
      resetForm()
      await load()
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function doToggle(ch: NotifyChannel) {
    setErr('')
    try {
      await setNotifyChannelEnabled(ch.id, !ch.enabled)
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  async function doTest(ch: NotifyChannel) {
    setErr('')
    setNote('')
    try {
      await testNotifyChannel(ch.id)
      setNote(`Test alert sent to “${ch.name}”. Check the channel.`)
    } catch (e) {
      setErr(`Test to “${ch.name}” failed: ${errMessage(e)}`)
    }
  }

  async function doDelete(ch: NotifyChannel) {
    if (!confirm(`Delete channel “${ch.name}”? Alerts will stop going there.`)) return
    setErr('')
    try {
      await deleteNotifyChannel(ch.id)
      await load()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  const secretLabel =
    type === 'dingtalk'
      ? 'Signing secret (加签, optional)'
      : 'Secret (optional)'

  return (
    <>
      <div className="section">
        <h2>New channel</h2>
        <p className="muted">
          Alert destinations. The webhook URL and signing secret are stored encrypted and are
          <strong> never shown again</strong> after saving.
        </p>

        <label htmlFor="ch-type">Type</label>
        <select id="ch-type" value={type} onChange={(e) => setType(e.target.value as NotifyChannelType)}>
          {CHANNEL_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        <label htmlFor="ch-name">Name</label>
        <input
          id="ch-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. ops-dingtalk"
          autoComplete="off"
        />

        <label htmlFor="ch-url">Webhook URL (https)</label>
        <input
          id="ch-url"
          type="text"
          className="mono"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://oapi.dingtalk.com/robot/send?access_token=…"
          autoComplete="off"
        />

        <label htmlFor="ch-secret">{secretLabel}</label>
        <input
          id="ch-secret"
          type="password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder={type === 'dingtalk' ? 'SEC…' : ''}
          autoComplete="off"
        />

        {type === 'webhook' && (
          <>
            <label htmlFor="ch-method">Method</label>
            <input
              id="ch-method"
              type="text"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              placeholder="POST"
              autoComplete="off"
            />
            <label htmlFor="ch-template">Body template (optional)</label>
            <textarea
              id="ch-template"
              className="mono"
              rows={3}
              value={template}
              onChange={(e) => setTemplate(e.target.value)}
              placeholder={'{"text": {{.Message | json}}}'}
            />
          </>
        )}

        <label>Events (none selected = all)</label>
        <div className="checks">
          {EVENT_KINDS.map((k) => (
            <label key={k} className="check">
              <input type="checkbox" checked={events.includes(k)} onChange={() => toggleEvent(k)} />
              {EVENT_LABELS[k]}
            </label>
          ))}
        </div>

        <div className="row2">
          <div>
            <label htmlFor="ch-headroom">Min headroom % (quota_low gate)</label>
            <input
              id="ch-headroom"
              type="text"
              value={minHeadroom}
              onChange={(e) => setMinHeadroom(e.target.value)}
              placeholder="0"
              inputMode="numeric"
              autoComplete="off"
            />
          </div>
          <div>
            <label htmlFor="ch-dedup">Dedup window (seconds)</label>
            <input
              id="ch-dedup"
              type="text"
              value={dedup}
              onChange={(e) => setDedup(e.target.value)}
              placeholder="0"
              inputMode="numeric"
              autoComplete="off"
            />
          </div>
        </div>

        <button disabled={busy || name.trim() === '' || url.trim() === ''} onClick={doCreate}>
          {busy ? 'Creating…' : 'Create channel'}
        </button>
      </div>

      <div className="section">
        <h2>Channels ({channels.length})</h2>
        {err && <p className="err">{err}</p>}
        {note && <p className="hint">{note}</p>}
        {channels.length === 0 ? (
          <p className="muted">No channels yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Events</th>
                <th>State</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {channels.map((ch) => (
                <tr key={ch.id}>
                  <td>{ch.name}</td>
                  <td className="mono">{ch.type}</td>
                  <td className="muted">
                    {ch.events.length === 0 ? 'all events' : `${ch.events.length} selected`}
                  </td>
                  <td>
                    <span className={ch.enabled ? 'pill ok' : 'pill'}>
                      {ch.enabled ? 'enabled' : 'disabled'}
                    </span>
                  </td>
                  <td className="right">
                    <button className="ghost small" onClick={() => doTest(ch)}>
                      Test
                    </button>{' '}
                    <button className="ghost small" onClick={() => doToggle(ch)}>
                      {ch.enabled ? 'Disable' : 'Enable'}
                    </button>{' '}
                    <button className="danger small" onClick={() => doDelete(ch)}>
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
