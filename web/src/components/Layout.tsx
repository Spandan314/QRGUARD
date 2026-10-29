import { Link, NavLink, Outlet } from 'react-router'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../hooks/useTheme'
import { Icon } from './Icon'

// Every page is one tap away on the main bar: no hidden menus. On phones the bar wraps.
const NAV = [
  { to: '/', label: 'Check anything', end: true },
  { to: '/check/url', label: 'Link' },
  { to: '/check/message', label: 'Message' },
  { to: '/check/qr', label: 'QR code' },
  { to: '/check/screenshot', label: 'Screenshot' },
  { to: '/generate', label: 'Make a QR' },
  { to: '/history', label: 'History' },
  { to: '/tips', label: 'Safety tips' },
  { to: '/about', label: 'About' },
]

const navClass = ({ isActive }: { isActive: boolean }) =>
  `inline-flex min-h-11 items-center rounded-btn px-3 text-sm font-medium transition-colors ${
    isActive ? 'bg-panel text-ink ring-1 ring-line' : 'text-muted hover:text-ink'
  }`

function ThemeToggle() {
  const { theme, toggle } = useTheme()
  const next = theme === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className="inline-flex h-11 w-11 items-center justify-center rounded-btn border border-line text-ink hover:bg-panel"
      data-testid="theme-toggle"
    >
      <Icon name={theme === 'dark' ? 'sun' : 'moon'} className="h-[18px] w-[18px]" />
    </button>
  )
}

/** Sign in / Account (when sign-in is set up) and Admin (for admins), beside the theme switch. */
function AccountLinks() {
  const { client, user, profile } = useAuth()
  const link = ({ isActive }: { isActive: boolean }) =>
    `inline-flex min-h-11 items-center rounded-btn border px-3 text-sm font-medium ${
      isActive ? 'border-accent text-ink' : 'border-line text-ink hover:bg-panel'
    }`
  return (
    <>
      {profile?.admin ? (
        <NavLink to="/admin" className={link}>
          Admin
        </NavLink>
      ) : null}
      {client.mode !== 'off' ? (
        <NavLink to="/account" className={link}>
          {user ? 'Account' : 'Sign in'}
        </NavLink>
      ) : null}
    </>
  )
}

export function Layout() {
  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded-btn focus:bg-panel focus:p-2"
      >
        Skip to content
      </a>
      <header className="mx-auto w-full max-w-6xl px-4 sm:px-6">
        <div className="flex items-center justify-between gap-3 pt-3 pb-2">
          <Link to="/" className="font-display text-xl font-bold tracking-tight" aria-label="QRGUARD home">
            <span className="text-ink">QR</span>
            <span className="text-accent">GUARD</span>
          </Link>
          <div className="flex items-center gap-2">
            <AccountLinks />
            <ThemeToggle />
          </div>
        </div>
        <nav aria-label="Main" className="flex flex-wrap items-center gap-1 border-b border-line pb-2">
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end ?? false} className={navClass}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
        <Outlet />
      </main>
      <footer className="mx-auto w-full max-w-6xl px-4 sm:px-6">
        <div className="border-t border-line py-6 text-xs text-muted">
          <p>QRGUARD gives an automatic check, not a guarantee. We check links on our server, so your phone never opens them.</p>
          <p className="mt-1">In India, report financial fraud by calling 1930 or at cybercrime.gov.in.</p>
        </div>
      </footer>
    </div>
  )
}
