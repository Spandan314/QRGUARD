import { createBrowserRouter, type RouteObject } from 'react-router'
import { Layout } from './components/Layout'
import About from './pages/About'
import Account from './pages/Account'
import Admin from './pages/Admin'
import Dashboard from './pages/Dashboard'
import History from './pages/History'
import MessageCheck from './pages/MessageCheck'
import NotFound from './pages/NotFound'
import QrGenerator from './pages/QrGenerator'
import QrImageCheck from './pages/QrImageCheck'
import ScreenshotCheck from './pages/ScreenshotCheck'
import SecurityTips from './pages/SecurityTips'
import UrlCheck from './pages/UrlCheck'

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'check/url', element: <UrlCheck /> },
      { path: 'check/message', element: <MessageCheck /> },
      { path: 'check/screenshot', element: <ScreenshotCheck /> },
      { path: 'check/qr', element: <QrImageCheck /> },
      { path: 'generate', element: <QrGenerator /> },
      { path: 'history', element: <History /> },
      { path: 'account', element: <Account /> },
      { path: 'admin', element: <Admin /> },
      { path: 'tips', element: <SecurityTips /> },
      { path: 'about', element: <About /> },
      { path: '*', element: <NotFound /> },
    ],
  },
]

export const router = createBrowserRouter(routes)
