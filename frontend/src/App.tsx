import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PageSection, Spinner } from "@patternfly/react-core";
import { lazy, Suspense } from "react";
import { AppShell } from "./components/AppShell";
import { useSession } from "./hooks/useSession";
import { Login } from "./pages/Login";
import { Placeholder } from "./pages/Placeholder";

const CatalogDetail = lazy(() => import("./pages/CatalogDetail").then((module) => ({ default: module.CatalogDetail })));
const CatalogImport = lazy(() => import("./pages/CatalogImport").then((module) => ({ default: module.CatalogImport })));
const Catalogs = lazy(() => import("./pages/Catalogs").then((module) => ({ default: module.Catalogs })));
const Configuration = lazy(() => import("./pages/Configuration").then((module) => ({ default: module.Configuration })));
const HostConfiguration = lazy(() => import("./pages/HostConfiguration").then((module) => ({ default: module.HostConfiguration })));
const HostDetail = lazy(() => import("./pages/HostDetail").then((module) => ({ default: module.HostDetail })));
const HostOccurrenceDetail = lazy(() => import("./pages/HostOccurrenceDetail").then((module) => ({ default: module.HostOccurrenceDetail })));
const Hosts = lazy(() => import("./pages/Hosts").then((module) => ({ default: module.Hosts })));
const GlobalLog = lazy(() => import("./pages/GlobalLog").then((module) => ({ default: module.GlobalLog })));
const IssueDetail = lazy(() => import("./pages/IssueDetail").then((module) => ({ default: module.IssueDetail })));
const Issues = lazy(() => import("./pages/Issues").then((module) => ({ default: module.Issues })));
const Overview = lazy(() => import("./pages/Overview").then((module) => ({ default: module.Overview })));

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
      <Suspense fallback={<PageSection isCenterAligned><Spinner size="xl" aria-label="Loading page" /></PageSection>}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/log" element={<GlobalLog />} />
          <Route path="/hosts/:id/occurrences/:occurrenceId" element={<HostOccurrenceDetail />} />
          <Route path="/hosts/:id" element={<HostDetail />} />
          <Route path="/hosts/:id/configuration" element={<HostConfiguration />} />
          <Route path="/issues" element={<Issues />} />
          <Route path="/issues/:id" element={<IssueDetail />} />
          <Route path="/configuration" element={<Configuration />} />
          <Route path="/catalogs" element={<Catalogs />} />
          <Route path="/catalogs/import" element={<CatalogImport />} />
          <Route path="/catalogs/:id" element={<CatalogDetail />} />
          <Route path="*" element={<Placeholder />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}
