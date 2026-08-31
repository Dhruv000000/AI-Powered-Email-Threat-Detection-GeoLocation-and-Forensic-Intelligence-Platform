import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AnalyzeEmailPage } from './pages/AnalyzeEmailPage';
import { AnalysisResultPage } from './pages/AnalysisResultPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { ThreatMapPage } from './pages/ThreatMapPage';
import { IntelligenceGraphPage } from './pages/IntelligenceGraphPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { CasesPage } from './pages/CasesPage';
import { CaseDetailsPage } from './pages/CaseDetailsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';

export function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(true);

  return (
    <BrowserRouter>
      <Routes>
        {/* Public Login Route */}
        <Route
          path="/login"
          element={<LoginPage onLogin={() => setIsAuthenticated(true)} />}
        />

        {/* Authenticated Application Shell */}
        <Route
          path="/"
          element={
            isAuthenticated ? (
              <AppShell onLogout={() => setIsAuthenticated(false)} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="analyze" element={<AnalyzeEmailPage />} />
          <Route path="analyze/:emailId" element={<AnalysisResultPage />} />
          <Route path="threats" element={<ThreatsPage />} />
          <Route path="threats/:threatId" element={<AnalysisResultPage />} />
          <Route path="investigations" element={<InvestigationPage />} />
          <Route path="investigations/:investigationId" element={<InvestigationPage />} />
          <Route path="map" element={<ThreatMapPage />} />
          <Route path="graph" element={<IntelligenceGraphPage />} />
          <Route path="cases" element={<CasesPage />} />
          <Route path="cases/:caseId" element={<CaseDetailsPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          {/* Catch all fallback */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
