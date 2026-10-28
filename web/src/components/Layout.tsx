import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet } from 'react-router'
import { useAuth } from '../context/AuthContext'
import { useTheme } from '../hooks/useTheme'
import { Icon } from './Icon'

const PRIMARY = [
  { to: '/', label: 'Airlock', end: true },
  { to: '/history', label: 'History' },
  { to: '/tips', label: 'Scam guide' },
]

const navClass = ({ isActive }: { isActive: boolean }) =>
  `inline-flex min-h-11 items-center rounded-btn px-3.5 text-sm font-medium transition-colors ${
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

/** Everything that is not in the three main links, so every existing page stays one click away. */
function MoreMenu() {
  const { client, user, profile } = useAuth()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (event: MouseEvent) => {
      if (box.current && !box.current.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const items = [
    { to: '/check/url', label: 'Check a link' },
    { to: '/check/message', label: 'Check a message' },
    { to: '/check/qr', label: 'Check a QR code' },
    { to: '/check/screenshot', label: 'Check a screenshot' },
    { to: '/generate', label: 'Make a QR' },
    { to: '/about', label: 'About' },
    ...(client.mode !== 'off' ? [{ to: '/account', label: user ? 'Account' : 'Sign in' }] : []),
    ...(profile?.admin ? [{ to: '/admin', label: 'Admin' }] : []),
  ]
  return (
    <div className="relative" ref={box}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls="more-menu"
        onClick={() => setOpen(!open)}
        className="inline-flex min-h-11 items-center gap-1.5 rounded-btn px-3.5 text-sm font-medium text-muted hover:text-ink"
      >
        More
        <Icon name="chevron-down" className="h-4 w-4" />
      </button>
      <ul
        id="more-menu"
        hidden={!open}
        className="absolute left-0 z-20 mt-2 w-56 rounded-panel sm:right-0 sm:left-auto border border-line bg-panel p-1.5"
      >
        {items.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex min-h-11 items-center rounded-btn px-3 text-sm ${isActive ? 'bg-panel-2 text-ink' : 'text-muted hover:bg-panel-2 hover:text-ink'}`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
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
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-line py-3">
          <Link to="/" className="font-display text-xl font-bold tracking-tight" aria-label="QRGUARD home">
            <span className="text-ink">QR</span>
            <span className="text-accent">GUARD</span>
          </Link>
          <div className="flex items-center gap-1 sm:order-last">
            <ThemeToggle />
          </div>
          <nav aria-label="Main" className="order-last flex w-full flex-wrap items-center gap-1 sm:order-none sm:w-auto">
            {PRIMARY.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end ?? false} className={navClass}>
                {item.label}
              </NavLink>
            ))}
            <MoreMenu />
          </nav>
        </div>
      </header>
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
        <Outlet />
      </main>
      <footer className="mx-auto w-full max-w-6xl px-4 sm:px-6">
        <div className="border-t border-line py-6 text-xs text-muted">
          <p>QRGUARD gives an automated security assessment, not a guarantee. Your device never opens the links you check.</p>
          <p className="mt-1">In India, report financial fraud by calling 1930 or at cybercrime.gov.in.</p>
        </div>
      </footer>
    </div>
  )
}
