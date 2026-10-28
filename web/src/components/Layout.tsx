import { useState } from 'react'
import { NavLink, Outlet } from 'react-router'
import { useAuth } from '../context/AuthContext'
import { Icon, type IconName } from './Icon'

type NavItem = { to: string; label: string; icon: IconName; end?: boolean }

const ANALYZE: NavItem[] = [
  { to: '/', label: 'Home', icon: 'home', end: true },
  { to: '/check/qr', label: 'QR code', icon: 'qr' },
  { to: '/check/url', label: 'Link', icon: 'link' },
  { to: '/check/message', label: 'Message', icon: 'message' },
  { to: '/check/screenshot', label: 'Screenshot', icon: 'screenshot' },
]
const TOOLS: NavItem[] = [
  { to: '/generate', label: 'Make a QR', icon: 'qr-plus' },
  { to: '/tips', label: 'Safety tips', icon: 'book-open' },
  { to: '/about', label: 'About', icon: 'info' },
]

function NavGroup({ title, items, onNavigate }: { title: string; items: NavItem[]; onNavigate: () => void }) {
  return (
    <div>
      <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{title}</p>
      <ul className="space-y-0.5">
        {items.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end ?? false}
              onClick={onNavigate}
              className={({ isActive }) =>
                `flex min-h-11 items-center gap-3 rounded-md border-l-2 px-3 text-sm font-medium transition-colors ${
                  isActive
                    ? 'border-teal-400 bg-slate-800 text-white'
                    : 'border-transparent text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`
              }
            >
              <Icon name={item.icon} className="h-[18px] w-[18px]" />
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function Layout() {
  const { client, user, profile } = useAuth()
  // Below the lg breakpoint the sidebar folds into a top bar with a Menu button.
  const [menuOpen, setMenuOpen] = useState(false)
  const account: NavItem[] = [
    ...(user ? [{ to: '/history', label: 'History', icon: 'history' as const }] : []),
    ...(profile?.admin ? [{ to: '/admin', label: 'Admin', icon: 'settings' as const }] : []),
    ...(client.mode !== 'off' ? [{ to: '/account', label: user ? 'Account' : 'Sign in', icon: 'user' as const }] : []),
  ]
  const close = () => setMenuOpen(false)
  return (
    <div className="min-h-screen lg:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded focus:bg-white focus:p-2 focus:text-slate-900">
        Skip to content
      </a>
      <aside className="bg-slate-900 text-slate-100 lg:fixed lg:inset-y-0 lg:flex lg:w-60 lg:flex-col lg:border-r lg:border-slate-800">
        <div className="flex h-16 items-center justify-between gap-3 px-4 lg:px-5">
          <NavLink to="/" onClick={close} className="flex items-center gap-2.5 text-lg font-bold tracking-tight">
            <img src="/qrguard-mark.svg" alt="" className="h-8 w-8" />
            <span>
              <span className="text-white">QR</span>
              <span className="text-teal-400">GUARD</span>
            </span>
          </NavLink>
          <button
            type="button"
            className="inline-flex min-h-11 items-center gap-2 rounded-md border border-slate-700 px-3 text-sm font-medium text-slate-200 hover:bg-slate-800 lg:hidden"
            aria-expanded={menuOpen}
            aria-controls="main-nav"
            onClick={() => setMenuOpen(!menuOpen)}
          >
            <Icon name={menuOpen ? 'close' : 'menu'} className="h-[18px] w-[18px]" />
            Menu
          </button>
        </div>
        <nav
          aria-label="Main"
          id="main-nav"
          className={`${menuOpen ? 'block' : 'hidden'} space-y-5 border-t border-slate-800 px-3 py-4 lg:block lg:flex-1 lg:overflow-y-auto lg:border-t-0`}
        >
          <NavGroup title="Analyze" items={ANALYZE} onNavigate={close} />
          <NavGroup title="Tools" items={TOOLS} onNavigate={close} />
          {account.length ? <NavGroup title="Account" items={account} onNavigate={close} /> : null}
        </nav>
        <p className="hidden border-t border-slate-800 px-5 py-4 text-xs leading-relaxed text-slate-500 lg:block">
          Automated assessment, not a guarantee. QRGUARD never opens the links you check.
        </p>
      </aside>
      <div className="flex min-h-screen flex-1 flex-col lg:pl-60">
        <main id="main" className="mx-auto w-full max-w-5xl flex-1 px-4 py-8 sm:px-6 lg:px-10">
          <Outlet />
        </main>
        <footer className="border-t border-slate-200 px-4 py-5 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
          <p>QRGUARD gives an automated security assessment, not a guarantee. It never opens the links you check.</p>
          <p className="mt-1">In India, report financial fraud by calling 1930 or at cybercrime.gov.in.</p>
        </footer>
      </div>
    </div>
  )
}
