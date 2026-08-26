import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { clearToken, getToken, observeAuth } from './auth'
import { Layout } from './components/Layout'
import { IncidentDetail } from './pages/IncidentDetail'
import { Incidents } from './pages/Incidents'
import { KnowledgeSearch } from './pages/KnowledgeSearch'
import { Login } from './pages/Login'

export default function App() {
  const [token, setTokenState] = useState<string | null>(getToken())

  useEffect(() => observeAuth(() => setTokenState(getToken())), [])

  if (!token) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="*" element={<Login />} />
        </Routes>
      </BrowserRouter>
    )
  }

  return (
    <BrowserRouter>
      <Layout onLogout={() => clearToken()}>
        <Routes>
          <Route path="/" element={<Navigate to="/incidents" replace />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/knowledge" element={<KnowledgeSearch />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
