import { Link } from 'react-router'

export default function NotFound() {
  return (
    <div className="space-y-3 text-center">
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Page not found</h1>
      <Link to="/" className="text-teal-700 underline dark:text-teal-400">
        Back to the home page
      </Link>
    </div>
  )
}
