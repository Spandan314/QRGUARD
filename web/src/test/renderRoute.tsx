import { render } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { AuthProvider } from '../context/AuthContext'
import { routes } from '../router'
import { NoAuthClient, type AuthClient } from '../services/auth'

export function renderRoute(path: string, client: AuthClient = new NoAuthClient()) {
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  return render(
    <AuthProvider client={client}>
      <RouterProvider router={router} />
    </AuthProvider>,
  )
}
