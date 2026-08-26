import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { IncidentDetail } from './pages/IncidentDetail'
import { Incidents } from './pages/Incidents'
import { KnowledgeSearch } from './pages/KnowledgeSearch'

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
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
