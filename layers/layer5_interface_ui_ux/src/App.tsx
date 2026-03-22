import { useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useSessionStore } from "./stores/useSessionStore";
import { AppShell } from "./layouts/AppShell";
import { AuthLayout } from "./layouts/AuthLayout";
import { RequireAuth } from "./providers/RequireAuth";

import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { ForgotPasswordPage } from "./pages/ForgotPasswordPage";
import { TermsPage } from "./pages/TermsPage";
import { PrivacyPage } from "./pages/PrivacyPage";
import { DashboardPage } from "./pages/DashboardPage";
import { OnboardingPage } from "./pages/OnboardingPage";
import { EndpointsPage } from "./pages/EndpointsPage";
import { EndpointDetailPage } from "./pages/EndpointDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { AlertsPage } from "./pages/AlertsPage";
import { CyclesPage } from "./pages/CyclesPage";
import { CycleDetailPage } from "./pages/CycleDetailPage";
import { TelemetryPage } from "./pages/TelemetryPage";
import { GraphPage } from "./pages/GraphPage";
import { NotesPage } from "./pages/NotesPage";
import { SimulatorPage } from "./pages/SimulatorPage";
import { SimulationDetailPage } from "./pages/SimulationDetailPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TasksPage } from "./pages/TasksPage";
import { NotFoundPage } from "./pages/NotFoundPage";

import "./styles/tokens.css";
import "./app-shell.css";

export default function App() {
  const restoreSession = useSessionStore((s) => s.restoreSession);

  useEffect(() => {
    restoreSession();
  }, [restoreSession]);

  return (
    <BrowserRouter>
      <Routes>
        {/* Auth routes (no shell) */}
        <Route element={<AuthLayout />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        </Route>

        {/* Legal pages (standalone) */}
        <Route path="/terms" element={<TermsPage />} />
        <Route path="/privacy" element={<PrivacyPage />} />

        {/* Authenticated routes (with shell) */}
        <Route
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/onboarding" element={<OnboardingPage />} />
          <Route path="/endpoints" element={<EndpointsPage />} />
          <Route path="/endpoints/:entityId" element={<EndpointDetailPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/cycles" element={<CyclesPage />} />
          <Route path="/cycles/:cycleId" element={<CycleDetailPage />} />
          <Route path="/cycles/:cycleId/telemetry" element={<TelemetryPage />} />
          <Route path="/graph" element={<GraphPage />} />
          <Route path="/notes" element={<NotesPage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/simulator" element={<SimulatorPage />} />
          <Route path="/simulator/:simulationId" element={<SimulationDetailPage />} />
          <Route path="/settings/*" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
