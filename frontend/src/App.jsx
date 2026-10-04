import { useCallback, useMemo } from "react";
import { AppShell } from "./components/Shell.jsx";
import { ErrorState, LoadingState } from "./components/States.jsx";
import { AppDataContext, useApi } from "./hooks.js";
import Account from "./pages/Account.jsx";
import Analyze from "./pages/Analyze.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Files from "./pages/Files.jsx";
import History from "./pages/History.jsx";
import Lab from "./pages/Lab.jsx";
import Media from "./pages/Media.jsx";
import Network from "./pages/Network.jsx";
import Phishing from "./pages/Phishing.jsx";
import { NotFound, Planned } from "./pages/Planned.jsx";
import Reports from "./pages/Reports.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import Vulns from "./pages/Vulns.jsx";
import Text from "./pages/Text.jsx";
import Settings from "./pages/Settings.jsx";
import Sources from "./pages/Sources.jsx";
import { useRouter } from "./router.jsx";

// Pages that really work. Everything else renders the honest "not available yet" page.
const PAGES = { dashboard: Dashboard, analyze: Analyze, phishing: Phishing, account: Account,
  files: Files, network: Network, vulnerabilities: Vulns, text: Text, media: Media, lab: Lab,
  history: History, reports: Reports, sources: Sources, settings: Settings };

export default function App() {
  const { path } = useRouter();
  const cfg = useApi("/config");
  const mods = useApi("/modules");
  const refreshConfig = cfg.reload;
  const stableRefresh = useCallback(() => refreshConfig(), [refreshConfig]);
  const value = useMemo(
    () => ({ config: cfg.data, modules: mods.data, refreshConfig: stableRefresh }),
    [cfg.data, mods.data, stableRefresh]
  );

  if ((cfg.loading && !cfg.data) || (mods.loading && !mods.data)) return <LoadingState label="Starting CyberShield X" />;
  if (cfg.error || mods.error) {
    return (
      <ErrorState title="CyberShield X can't reach its server" message={(cfg.error || mods.error).message}
        onRetry={() => { cfg.reload(); mods.reload(); }} />
    );
  }

  const module = mods.data.modules.find((m) => m.path === path);
  // Saved-scan detail lives under /history/:id.
  if (path.startsWith("/history/") && path.length > "/history/".length) {
    const scanId = decodeURIComponent(path.slice("/history/".length));
    return (
      <AppDataContext.Provider value={value}>
        <AppShell modules={mods.data.modules} title="Scan report" demoMode={cfg.data.demo_mode}>
          <ScanDetail scanId={scanId} />
        </AppShell>
      </AppDataContext.Provider>
    );
  }
  const Page = module && module.status === "available" ? PAGES[module.key] : null;
  const title = module ? module.label : "Page not found";

  return (
    <AppDataContext.Provider value={value}>
      <AppShell modules={mods.data.modules} title={title} demoMode={cfg.data.demo_mode}>
        {Page ? <Page /> : module ? <Planned module={module} /> : <NotFound />}
      </AppShell>
    </AppDataContext.Provider>
  );
}
