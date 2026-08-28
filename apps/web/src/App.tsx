import { Navigate, Route, Routes } from "react-router-dom";
import { useAuthStore } from "./store/auth";
import { useRealtime } from "./api/ws";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import CommandCenter from "./pages/CommandCenter";
import AttackSurface from "./pages/AttackSurface";
import Assets from "./pages/Assets";
import AssetDetail from "./pages/AssetDetail";
import Offensive from "./pages/Offensive";
import EngagementDetail from "./pages/EngagementDetail";
import Vulnerabilities from "./pages/Vulnerabilities";
import FindingDetail from "./pages/FindingDetail";
import Evidence from "./pages/Evidence";
import AttackPaths from "./pages/AttackPaths";
import SOC from "./pages/SOC";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Hunting from "./pages/Hunting";
import Detection from "./pages/Detection";
import Response from "./pages/Response";
import Purple from "./pages/Purple";
import Remediation from "./pages/Remediation";
import Reports from "./pages/Reports";
import Copilot from "./pages/Copilot";
import Admin from "./pages/Admin";

function RequireAuth({ children }: { children: JSX.Element }) {
  const { accessToken } = useAuthStore();
  return accessToken ? children : <Navigate to="/login" replace />;
}

export default function App() {
  useRealtime();
  const { accessToken } = useAuthStore();
  if (accessToken) {
    return (
      <Routes>
        <Route element={<RequireAuth><Layout /></RequireAuth>}>
          <Route path="/" element={<CommandCenter />} />
          <Route path="/attack-surface" element={<AttackSurface />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/assets/:id" element={<AssetDetail />} />
          <Route path="/offensive" element={<Offensive />} />
          <Route path="/offensive/:id" element={<EngagementDetail />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/vulnerabilities/:id" element={<FindingDetail />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/soc" element={<SOC />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/hunting" element={<Hunting />} />
          <Route path="/detection" element={<Detection />} />
          <Route path="/response" element={<Response />} />
          <Route path="/purple" element={<Purple />} />
          <Route path="/remediation" element={<Remediation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/copilot" element={<Copilot />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    );
  }
  return <Login />;
}
