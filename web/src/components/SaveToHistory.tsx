import { useState } from 'react'
import { Link } from 'react-router'
import { useAuth } from '../context/AuthContext'

/** Opt-in "save to my history" choice. Signed-out users see a hint instead. */
export function useSaveOption() {
  const { user, profile } = useAuth()
  const [choice, setChoice] = useState<boolean | null>(null)
  const available = Boolean(user && profile)
  const save = available && (choice ?? profile?.save_history ?? false)
  return { save, available, setSave: setChoice }
}

export function SaveToHistory({ option }: { option: ReturnType<typeof useSaveOption> }) {
  const { user, client } = useAuth()
  if (!option.available) {
    if (client.mode === 'off' || user) return null
    return (
      <p className="text-sm text-slate-500 dark:text-slate-400">
        <Link to="/account" className="text-teal-700 underline dark:text-teal-400">
          Sign in
        </Link>{' '}
        to keep a private history of your checks (only the verdict is saved, never your content).
      </p>
    )
  }
  return (
    <label className="flex items-center gap-2 text-sm">
      <input type="checkbox" checked={option.save} onChange={(event) => option.setSave(event.target.checked)} />
      Save the result to my history (only the verdict, never the content)
    </label>
  )
}
