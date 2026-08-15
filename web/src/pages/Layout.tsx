import type { ReactNode } from 'react'
import { logout, type Me } from '../api'

export type Page = 'dashboard' | 'accounts' | 'policies' | 'endpoints' | 'keys'

const NAV: { id: Page; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'accounts', label: 'Accounts' },
  { id: 'policies', label: 'Policies' },
  { id: 'endpoints', label: 'Endpoints' },
  { id: 'keys', label: 'API keys' },
]

export function Layout({
  me,
  active,
  onNav,
  onLogout,
  children,
}: {
  me: Me
  active: Page
  onNav: (p: Page) => void
  onLogout: () => void
  children: ReactNode
}) {
  async function doLogout() {
    try {
      await logout()
    } finally {
      onLogout()
    }
  }

  return (
    <div className="app">
      <div className="topbar">
        <div>
          <span className="brand">poolgate</span> <span className="muted">· {me.operator}</span>
        </div>
        <button className="ghost" onClick={doLogout}>
          Sign out
        </button>
      </div>

      <div className="tabs">
        {NAV.map((n) => (
          <button key={n.id} className={active === n.id ? 'active' : ''} onClick={() => onNav(n.id)}>
            {n.label}
          </button>
        ))}
      </div>

      {children}
    </div>
  )
}
