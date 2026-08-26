const TOKEN_KEY = 'sentinelx_token'
const AUTH_EVENT = 'sentinelx-auth'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
  window.dispatchEvent(new Event(AUTH_EVENT))
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  window.dispatchEvent(new Event(AUTH_EVENT))
}

/** Re-renders the app when the token changes (login/logout/401 eviction). */
export function observeAuth(callback: () => void): () => void {
  window.addEventListener(AUTH_EVENT, callback)
  window.addEventListener('storage', callback)
  return () => {
    window.removeEventListener(AUTH_EVENT, callback)
    window.removeEventListener('storage', callback)
  }
}

interface TokenResponse {
  access_token: string
  role: string
}

export async function login(username: string, password: string): Promise<string> {
  const base = import.meta.env.VITE_API_BASE ?? ''
  const res = await fetch(`${base}/api/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) throw new Error(res.status === 401 ? 'Invalid credentials' : `Login failed (${res.status})`)
  const data = (await res.json()) as TokenResponse
  setToken(data.access_token)
  return data.role
}
