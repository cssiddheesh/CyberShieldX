import { useEffect, useState } from "react";
import { api } from "../api.js";
import { CoverageRing, ThreatChart } from "../components/Charts.jsx";
import Icon from "../components/Icon.jsx";
import { RecentScans } from "../components/Scans.jsx";
import { SourceStatus } from "../components/Sources.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { TYPE_LABELS } from "../format.js";
import { useAppData, useApi } from "../hooks.js";
import { Link, useRouter } from "../router.jsx";

function UniversalScan() {
  const { navigate } = useRouter();
  const [value, setValue] = useState("");
  const [ident, setIdent] = useState(null);
  const [failed, setFailed] = useState(null);

  useEffect(() => {
    if (!value.trim()) {
      setIdent(null);
      setFailed(null);
      return undefined;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      api.post("/identify", { input: value }, { signal: controller.signal })
        .then((result) => { setIdent(result); setFailed(null); })
        .catch((error) => { if (error.name !== "AbortError") setFailed(error.message); });
    }, 250);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [value]);

  const canOpen = ident?.module && ident.module_available;
  const submit = (event) => {
    event.preventDefault();
    if (canOpen) navigate(`${ident.module_path}?q=${encodeURIComponent(ident.normalized)}`);
  };

  let hint = "Links, domains, IP addresses, file hashes and CVE IDs are recognized. Passwords are checked in Account Security, never here.";
  let tone = "";
  if (failed) { hint = failed; tone = "is-error"; }
  else if (ident) {
    if (ident.indicator_type === "unknown") { hint = ident.notes[0] || "Not recognized."; tone = "is-warn"; }
    else {
      hint = `Detected ${TYPE_LABELS[ident.indicator_type]}. ${canOpen ? `Opens in ${ident.module_label}.` : `${ident.module_label} isn't available yet.`}`;
      tone = canOpen ? "is-ok" : "is-warn";
    }
  }

  return (
    <form className="scan-form" onSubmit={submit}>
      <label htmlFor="universal-input" className="scan-label">What do you want to check?</label>
      <div className="scan-field">
        <Icon name="analyze" size={20} />
        <input id="universal-input" type="text" value={value} onChange={(e) => setValue(e.target.value)}
          placeholder="Paste a link, domain, IP address, file hash or CVE ID" maxLength={2048}
          autoComplete="off" spellCheck="false" />
        <button className="btn btn-primary" type="submit" disabled={!canOpen}>Analyze</button>
      </div>
      <p className={`scan-hint ${tone}`} aria-live="polite">{hint}</p>
    </form>
  );
}

export default function Dashboard() {
  const { modules } = useAppData();
  const { data, error, loading, reload } = useApi("/dashboard");

  if (loading && !data) return <LoadingState label="Loading dashboard" />;
  if (error) return <ErrorState title="The dashboard could not load" message={error.message} onRetry={reload} />;

  const needKey = data.sources.items.filter((s) => s.state === "NOT_CONFIGURED").length;
  return (
    <div className="stack">
      <section className="hero">
        <div className="hero-main panel">
          <h2 className="hero-title">Detect, correlate, explain, report.</h2>
          <p className="hero-lead">
            CyberShield X looks at a digital threat from several angles at once, lines the evidence up, and explains
            what it found in plain language.
          </p>
          <UniversalScan />
          <p className="fine-print">
            Local analysis runs on this computer. When an external intelligence source is used, the indicator may be sent to that provider.
          </p>
        </div>
        <div className="hero-ring panel">
          <h2 className="panel-title">360° coverage</h2>
          <CoverageRing dimensions={modules.dimensions} />
        </div>
      </section>

      <section className="stat-strip" aria-label="Summary">
        <div className="stat">
          <span className="stat-label">Scans saved</span>
          <span className="stat-value">{data.total_scans}</span>
          {data.demo_scans > 0 && <span className="stat-note">{data.demo_scans} demonstration</span>}
        </div>
        <div className="stat">
          <span className="stat-label">High or critical</span>
          <span className="stat-value">{data.high_critical}</span>
          <span className="stat-note">across all saved scans</span>
        </div>
        <div className="stat">
          <span className="stat-label">Intelligence sources ready</span>
          <span className="stat-value">{data.sources.ready}<small> of {data.sources.total}</small></span>
          {needKey > 0 && <span className="stat-note">{needKey} need an API key</span>}
        </div>
        <div className="stat">
          <span className="stat-label">Overall status</span>
          <span className={`stat-value stat-posture posture-${data.posture.level}`}>{data.posture.label}</span>
          <span className="stat-note">from your recent scans</span>
        </div>
      </section>

      <section className="two-col">
        <div className="panel">
          <h2 className="panel-title">Threat distribution</h2>
          <ThreatChart distribution={data.distribution} total={data.total_scans} />
        </div>
        <div className="panel">
          <div className="panel-head">
            <h2 className="panel-title">Intelligence sources</h2>
            <Link to="/sources" className="text-link">View all</Link>
          </div>
          <ul className="source-list">
            {data.sources.items.map((s) => <SourceStatus key={s.key} source={s} />)}
          </ul>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">Recent scans</h2>
          <Link to="/history" className="text-link">View history</Link>
        </div>
        <RecentScans scans={data.recent} compact />
      </section>
    </div>
  );
}
