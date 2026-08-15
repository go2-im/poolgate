import { useCallback, useEffect, useState } from 'react'
import { currentUser, type Me } from './api'
import { Login } from './pages/Login'
import { Layout, type Page } from './pages/Layout'
import { Dashboard } from './pages/Dashboard'
import { Accounts } from './pages/Accounts'
import { PolicyGroups } from './pages/PolicyGroups'
import { Endpoints } from './pages/Endpoints'
import { ApiKeys } from './pages/ApiKeys'

type State = { phase: 'loading' } | { phase: 'anon' } | { phase: 'authed'; me: Me }

export function App() {
  const [state, setState] = useState<State>({ phase: 'loading' })
  const [page, setPage] = useState<Page>('dashboard')

  const refresh = useCallback(async () => {
    try {
      const me = await currentUser()
      setState(me ? { phase: 'authed', me } : { phase: 'anon' })
    } catch {
      // A transient error (server down) — treat as anonymous so the login page
      // shows rather than a blank screen.
      setState({ phase: 'anon' })
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  if (state.phase === 'loading') {
    return (
      <div className="center">
        <p className="muted">Loading…</p>
      </div>
    )
  }
  if (state.phase === 'anon') {
    return <Login onAuthed={refresh} />
  }
  return (
    <Layout me={state.me} active={page} onNav={setPage} onLogout={refresh}>
      {page === 'dashboard' && <Dashboard />}
      {page === 'accounts' && <Accounts />}
      {page === 'policies' && <PolicyGroups />}
      {page === 'endpoints' && <Endpoints />}
      {page === 'keys' && <ApiKeys />}
    </Layout>
  )
}
