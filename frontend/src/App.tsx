import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PageSection, Spinner } from "@patternfly/react-core";
import { AppShell } from "./components/AppShell";
import { useSession } from "./hooks/useSession";
import { CatalogDetail } from "./pages/CatalogDetail";
import { Catalogs } from "./pages/Catalogs";
import { Configuration } from "./pages/Configuration";
import { HostConfiguration } from "./pages/HostConfiguration";
import { HostDetail } from "./pages/HostDetail";
import { HostOccurrenceDetail } from "./pages/HostOccurrenceDetail";
import { Hosts } from "./pages/Hosts";
import { IssueDetail } from "./pages/IssueDetail";
import { Issues } from "./pages/Issues";
import { Overview } from "./pages/Overview";
import { Login } from "./pages/Login";
import { Placeholder } from "./pages/Placeholder";

export function App() {
  const location = useLocation();
  const session = useSession();

  if (location.pathname === "/login") {
    return <Login />;
  }

  if (session.isLoading) {
    return (
      <PageSection isCenterAligned>
        <Spinner size="xl" />
      </PageSection>
    );
  }

  if (session.isError) {
    return <Navigate to="/login" replace />;
  }

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/hosts/:id/occurrences/:occurrenceId" element={<HostOccurrenceDetail />} />
        <Route path="/hosts/:id" element={<HostDetail />} />
        <Route path="/hosts/:id/configuration" element={<HostConfiguration />} />
        <Route path="/issues" element={<Issues />} />
        <Route path="/issues/:id" element={<IssueDetail />} />
        <Route path="/configuration" element={<Configuration />} />
        <Route path="/catalogs" element={<Catalogs />} />
        <Route path="/catalogs/:id" element={<CatalogDetail />} />
        <Route path="*" element={<Placeholder />} />
      </Routes>
    </AppShell>
  );
}
