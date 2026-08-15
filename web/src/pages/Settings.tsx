import { useEffect, useState } from 'react'
import {
  getSettings,
  registerAdditionalPasskey,
  revokeAllSessions,
  webauthnSupported,
  type Me,
  type Settings as SettingsData,
} from '../api'
import { errMessage } from './ui'

export function Settings({ me, onSignedOut }: { me: Me; onSignedOut: () => void }) {
  const [settings, setSettings] = useState<SettingsData | null>(null)
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [label, setLabel] = useState('')

  useEffect(() => {
    getSettings()
      .then(setSettings)
      .catch((e) => setErr(errMessage(e)))
  }, [])

  async function addPasskey() {
    setErr('')
    setNote('')
    setBusy(true)
    try {
      await registerAdditionalPasskey(label.trim() || 'passkey')
      setLabel('')
      setNote('New passkey registered. You can now sign in with it on this device.')
    } catch (e) {
      setErr(errMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function revokeAll() {
    if (
      !confirm(
        'Revoke ALL sessions? Every signed-in browser — including this one — will be signed out immediately.',
      )
    )
      return
    setErr('')
    try {
      await revokeAllSessions()
      // The current session was revoked too; bounce back to the login screen.
      onSignedOut()
    } catch (e) {
      setErr(errMessage(e))
    }
  }

  return (
    <>
      <div className="section">
        <h2>Session</h2>
        <table>
          <tbody>
            <tr>
              <th>Operator</th>
              <td>{me.operator}</td>
            </tr>
            <tr>
              <th>Signed in</th>
              <td className="mono">{me.session.created_at}</td>
            </tr>
            <tr>
              <th>Last seen</th>
              <td className="mono">{me.session.last_seen_at}</td>
            </tr>
            <tr>
              <th>Expires</th>
              <td className="mono">{me.session.expires_at}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="section">
        <h2>Add a passkey</h2>
        <p className="muted">
          Register an additional passkey (e.g. a second device or a hardware key) for this operator.
          You stay signed in.
        </p>
        {!webauthnSupported() ? (
          <p className="err">This browser does not support WebAuthn.</p>
        ) : (
          <>
            <label htmlFor="pk-label">Label (optional)</label>
            <input
              id="pk-label"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. yubikey-5c"
              autoComplete="off"
            />
            <button disabled={busy} onClick={addPasskey}>
              {busy ? 'Waiting for authenticator…' : 'Register passkey'}
            </button>
          </>
        )}
        {note && <p className="hint">{note}</p>}
      </div>

      <div className="section">
        <h2>WebAuthn scope</h2>
        <p className="muted">
          Resolved once at startup from static config — passkeys are bound to this Relying Party ID
          and origin.
        </p>
        {settings ? (
          <table>
            <tbody>
              <tr>
                <th>Admin origin</th>
                <td className="mono">{settings.origin}</td>
              </tr>
              <tr>
                <th>External origin</th>
                <td className="mono">{settings.external_origin || '(synthesized from host:port)'}</td>
              </tr>
              <tr>
                <th>RP ID</th>
                <td className="mono">{settings.rp_id}</td>
              </tr>
              <tr>
                <th>Secure cookies</th>
                <td>{settings.secure ? 'yes (https)' : 'no (http loopback)'}</td>
              </tr>
            </tbody>
          </table>
        ) : (
          <p className="muted">Loading…</p>
        )}
      </div>

      <div className="section">
        <h2>Danger zone</h2>
        <p className="muted">
          Revoke every session. Use this if you think a session was compromised — all browsers must
          sign in again.
        </p>
        {err && <p className="err">{err}</p>}
        <button className="danger" onClick={revokeAll}>
          Revoke all sessions
        </button>
      </div>
    </>
  )
}
