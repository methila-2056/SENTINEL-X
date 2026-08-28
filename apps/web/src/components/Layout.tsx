import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { ThemeToggle } from './ThemeToggle'

export function Layout({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  return (
    <>
      <nav className="sidebar">
        <div className="logo">
          SENTINEL<span>-X</span>
        </div>
        <div className="tagline">Security Incident Intelligence</div>
        <ThemeToggle />
        <div className="sys-status">
          <span className="dot" /> SYSTEM ONLINE
        </div>
        <NavLink to="/incidents" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
          <span className="nav-ico">▣</span> Incidents
        </NavLink>
        <NavLink
          to="/investigations"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <span className="nav-ico">◈</span> Investigations
        </NavLink>
        <NavLink
          to="/knowledge"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <span className="nav-ico">◉</span> Threat Intelligence
        </NavLink>
        <button className="logout-button" type="button" onClick={onLogout}>
          Sign out
        </button>
      </nav>
      <main className="main">{children}</main>
    </>
  )
}
