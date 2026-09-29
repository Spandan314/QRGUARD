import { NavLink, Outlet } from 'react-router'

const LINKS = [
  { to: '/', label: 'Home', end: true },
  { to: '/check/url', label: 'Link' },
  { to: '/check/message', label: 'Message' },
  { to: '/check/screenshot', label: 'Screenshot' },
  { to: '/check/qr', label: 'QR image' },
  { to: '/generate', label: 'Make a QR' },
  { to: '/tips', label: 'Safety tips' },
  { to: '/about', label: 'About' },
]

export function Layout() {
  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:m-2 focus:rounded focus:bg-white focus:p-2">
        Skip to content
      </a>
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <NavLink to="/" className="flex items-center gap-2 text-xl font-bold text-teal-700 dark:text-teal-400">
            <img src="/shield.svg" alt="" className="h-7 w-7" />
            QRGUARD
          </NavLink>
          <nav aria-label="Main">
            <ul className="flex flex-wrap gap-1 text-sm">
              {LINKS.map((link) => (
                <li key={link.to}>
                  <NavLink
                    to={link.to}
                    end={link.end ?? false}
                    className={({ isActive }) =>
                      `inline-block min-h-11 rounded-lg px-3 py-2.5 ${
                        isActive
                          ? 'bg-teal-700 text-white'
                          : 'text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-800'
                      }`
                    }
                  >
                    {link.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>
      <main id="main" className="mx-auto w-full max-w-5xl flex-1 px-4 py-8">
        <Outlet />
      </main>
      <footer className="border-t border-slate-200 py-6 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        <p>QRGUARD gives an automated security assessment, not a guarantee. It never opens the links you check.</p>
        <p className="mt-1">
          In India, report financial fraud by calling 1930 or at cybercrime.gov.in.
        </p>
      </footer>
    </div>
  )
}
