import { useState } from 'react'
import {
  ApiError,
  login,
  loginWithRecoveryCode,
  register,
  webauthnSupported,
} from '../api'

type Tab = 'signin' | 'setup' | 'recovery'

export function Login({ onAuthed }: { onAuthed: () => void }) {
  const [tab, setTab] = useState<Tab>('signin')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [bootstrap, setBootstrap] = useState('')
  const [label, setLabel] = useState('')
  const [code, setCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)

  const supported = webauthnSupported()

  function fail(e: unknown) {
    if (e instanceof ApiError) setErr(e.message)
    else if (e instanceof Error) setErr(e.message)
    else setErr('unexpected error')
  }

  async function doSignin() {
    setErr('')
    setBusy(true)
    try {
      await login()
      onAuthed()
    } catch (e) {
      fail(e)
    } finally {
      setBusy(false)
    }
  }

  async function doSetup() {
    setErr('')
    setBusy(true)
    try {
      const r = await register(bootstrap.trim(), label.trim())
      if (r.recovery_codes && r.recovery_codes.length > 0) {
        // Show the one-time codes; the user continues into the app after saving.
        setRecoveryCodes(r.recovery_codes)
      } else {
        onAuthed()
      }
    } catch (e) {
      fail(e)
    } finally {
      setBusy(false)
    }
  }

  async function doRecovery() {
    setErr('')
    setBusy(true)
    try {
      await loginWithRecoveryCode(code.trim())
      onAuthed()
    } catch (e) {
      fail(e)
    } finally {
      setBusy(false)
    }
  }

  if (recoveryCodes) {
    return (
      <div className="center">
        <div className="card">
          <h1 className="brand">Save your recovery codes</h1>
          <p className="subtle">
            Shown once. Store them somewhere safe — each can recover admin access if you lose your
            passkey.
          </p>
          <div className="codes">{recoveryCodes.join('\n')}</div>
          <button onClick={onAuthed}>I&rsquo;ve saved them — continue</button>
        </div>
      </div>
    )
  }

  return (
    <div className="center">
      <div className="card">
        <h1 className="brand">poolgate</h1>
        <p className="subtle">Passkey-protected admin</p>

        <div className="tabs">
          <button className={tab === 'signin' ? 'active' : ''} onClick={() => setTab('signin')}>
            Sign in
          </button>
          <button className={tab === 'setup' ? 'active' : ''} onClick={() => setTab('setup')}>
            First-time setup
          </button>
          <button className={tab === 'recovery' ? 'active' : ''} onClick={() => setTab('recovery')}>
            Recovery code
          </button>
        </div>

        {!supported && (
          <p className="err">This browser does not support passkeys (WebAuthn).</p>
        )}

        {tab === 'signin' && (
          <>
            <p className="hint">Authenticate with a registered passkey (Touch ID, security key, or your phone via QR).</p>
            <button disabled={busy || !supported} onClick={doSignin}>
              {busy ? 'Waiting for passkey…' : 'Sign in with passkey'}
            </button>
          </>
        )}

        {tab === 'setup' && (
          <>
            <label htmlFor="bt">Bootstrap token</label>
            <input
              id="bt"
              type="password"
              value={bootstrap}
              onChange={(e) => setBootstrap(e.target.value)}
              placeholder="from `poolgate init` / `admin reset-auth`"
              autoComplete="off"
            />
            <label htmlFor="lbl">Passkey label (optional)</label>
            <input
              id="lbl"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. laptop-touchid"
              autoComplete="off"
            />
            <button disabled={busy || !supported || bootstrap.trim() === ''} onClick={doSetup}>
              {busy ? 'Registering…' : 'Register first passkey'}
            </button>
            <p className="hint">Use the one-time token printed by the CLI to register the first passkey. To use a phone, pick your browser's cross-device / QR option.</p>
          </>
        )}

        {tab === 'recovery' && (
          <>
            <label htmlFor="rc">Recovery code</label>
            <input
              id="rc"
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="one-time recovery code"
              autoComplete="off"
            />
            <button disabled={busy || code.trim() === ''} onClick={doRecovery}>
              {busy ? 'Verifying…' : 'Use recovery code'}
            </button>
          </>
        )}

        <p className="err">{err}</p>
      </div>
    </div>
  )
}
