import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

export function Layout({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  return (
    <>
      <nav className="sidebar">
        <div className="logo">
          SENTINEL<span>-X</span>
        </div>
        <div className="tagline">Security Incident Intelligence</div>
        <NavLink to="/incidents" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
          Incidents
        </NavLink>
        <NavLink
          to="/investigations"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          Investigations
        </NavLink>
        <NavLink
          to="/knowledge"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          Threat Intelligence
        </NavLink>
        <button className="logout-button" type="button" onClick={onLogout}>
          Sign out
        </button>
      </nav>
      <main className="main">{children}</main>
    </>
  )
}
