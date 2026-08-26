import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

export function Layout({ children }: { children: ReactNode }) {
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
          to="/knowledge"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          Threat Intelligence
        </NavLink>
      </nav>
      <main className="main">{children}</main>
    </>
  )
}
