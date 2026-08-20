import { useState, type ReactNode } from 'react'
import { logout, type Me } from '../api'

export type Page =
  | 'dashboard'
  | 'accounts'
  | 'policies'
  | 'endpoints'
  | 'keys'
  | 'notifications'
  | 'monitor'
  | 'settings'

type NavItem = { id: Page; label: string; icon: string }

const NAV: { label: string; items: NavItem[] }[] = [
  {
    label: 'Observe',
    items: [
      { id: 'dashboard', label: 'Overview', icon: 'OV' },
      { id: 'monitor', label: 'Live traffic', icon: 'LV' },
    ],
  },
  {
    label: 'Configure',
    items: [
      { id: 'accounts', label: 'Accounts', icon: 'AC' },
      { id: 'policies', label: 'Routing', icon: 'RT' },
      { id: 'endpoints', label: 'Endpoints', icon: 'EP' },
      { id: 'keys', label: 'API keys', icon: 'KY' },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'notifications', label: 'Alerts', icon: 'AL' },
      { id: 'settings', label: 'Settings', icon: 'ST' },
    ],
  },
]

const PAGE_META: Record<Page, { eyebrow: string; title: string; description: string }> = {
  dashboard: {
    eyebrow: 'System overview',
    title: 'Pool overview',
    description: 'Health, capacity, and routing readiness across the entire account pool.',
  },
  monitor: {
    eyebrow: 'Observe',
    title: 'Live traffic',
    description: 'Watch requests move through endpoints, policies, and pooled accounts.',
  },
  accounts: {
    eyebrow: 'Configure',
    title: 'Accounts',
    description: 'Manage credentials, quota headroom, and concurrency across the pool.',
  },
  policies: {
    eyebrow: 'Configure',
    title: 'Routing policies',
    description: 'Compose account groups and control how eligible traffic is distributed.',
  },
  endpoints: {
    eyebrow: 'Configure',
    title: 'Endpoints',
    description: 'Create stable OpenAI-compatible URLs backed by reusable routing policies.',
  },
  keys: {
    eyebrow: 'Configure',
    title: 'API keys',
    description: 'Issue revocable client credentials scoped to endpoints and networks.',
  },
  notifications: {
    eyebrow: 'System',
    title: 'Alerts',
    description: 'Send actionable pool-health events to your operational channels.',
  },
  settings: {
    eyebrow: 'System',
    title: 'Settings',
    description: 'Review sessions, passkeys, audit integrity, and WebAuthn scope.',
  },
}

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
  const [menuOpen, setMenuOpen] = useState(false)
  const meta = PAGE_META[active]

  async function doLogout() {
    try {
      await logout()
    } finally {
      onLogout()
    }
  }

  function navigate(page: Page) {
    onNav(page)
    setMenuOpen(false)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <div className={menuOpen ? 'app-shell menu-open' : 'app-shell'}>
      <button
        className="nav-scrim"
        aria-label="Close navigation"
        onClick={() => setMenuOpen(false)}
      />

      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand-row">
          <span className="brand-mark">PG</span>
          <span className="brand-name">poolgate</span>
          <span className="brand-version">admin</span>
        </div>

        <div className="workspace-card">
          <span className="workspace-mark">P</span>
          <span className="workspace-copy">
            <strong>Pool workspace</strong>
            <small>Admin console</small>
          </span>
        </div>

        <nav className="side-nav">
          {NAV.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-label">{group.label}</div>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={active === item.id ? 'nav-item active' : 'nav-item'}
                  onClick={() => navigate(item.id)}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>

        <button className="operator-card" onClick={doLogout} title="Sign out">
          <span className="operator-avatar">OP</span>
          <span className="operator-copy">
            <strong>{me.operator}</strong>
            <small>Passkey session</small>
          </span>
          <span className="operator-action">Sign out</span>
        </button>
      </aside>

      <div className="app-main">
        <header className="app-topbar">
          <button className="menu-button" onClick={() => setMenuOpen(true)} aria-label="Open navigation">
            Menu
          </button>
          <div className="breadcrumb">
            <span>Pool workspace</span>
            <span>/</span>
            <strong>{meta.title}</strong>
          </div>
          <div className="topbar-status">
            <span className="status-dot" />
            Session active
          </div>
        </header>

        <main className="page-content">
          <header className="page-heading">
            <p className="eyebrow">{meta.eyebrow}</p>
            <h1>{meta.title}</h1>
            <p>{meta.description}</p>
          </header>
          {children}
        </main>
      </div>
    </div>
  )
}
