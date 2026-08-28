import { useEffect, useState } from 'react'
import { getTheme, observeTheme, toggleTheme, type Theme } from '../theme'

export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = useState<Theme>(getTheme())

  useEffect(() => {
    const unsubscribe = observeTheme(() => setTheme(getTheme()))
    return unsubscribe
  }, [])

  return (
    <button
      type="button"
      className={`theme-toggle${className ? ` ${className}` : ''}`}
      onClick={() => toggleTheme()}
      title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      <span className="t-ico">{theme === 'dark' ? '☀️' : '🌙'}</span>
      {theme === 'dark' ? 'Light' : 'Dark'}
    </button>
  )
}
