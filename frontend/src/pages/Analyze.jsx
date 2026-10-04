import { useEffect, useState } from "react";
import { api } from "../api.js";
import Icon from "../components/Icon.jsx";
import { TYPE_LABELS } from "../format.js";
import { Link, useRouter } from "../router.jsx";
import { ScanProgress, useScan } from "./Phishing.jsx";
import Report from "../components/Report.jsx";
import { ErrorState } from "../components/States.jsx";

export default function Analyze() {
  const { navigate } = useRouter();
  const [value, setValue] = useState("");
  const [ident, setIdent] = useState(null);
  const [failed, setFailed] = useState(null);
  const [{ phase, step, report, error }, run] = useScan();

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
        .catch((err) => { if (err.name !== "AbortError") setFailed(err.message); });
    }, 250);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [value]);

  const submit = (e) => {
    e.preventDefault();
    if (!ident || ident.indicator_type === "unknown") return;
    if (ident.module === "phishing" && ident.module_available) run(ident.normalized);
    else if (ident.module_path) navigate(`${ident.module_path}?q=${encodeURIComponent(ident.normalized)}`);
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Universal Analyzer</h2>
        <p className="muted">Paste anything suspicious. CyberShield X identifies it and routes it to the right analyzer.</p>
        <form className="scan-form" onSubmit={submit}>
          <div className="scan-field">
            <Icon name="analyze" size={20} />
            <input type="text" value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="Link, domain, IP address, file hash or CVE ID" maxLength={2048}
              autoComplete="off" spellCheck="false" aria-label="Indicator to analyze" />
            <button className="btn btn-primary" type="submit"
              disabled={!ident || ident.indicator_type === "unknown" || !ident.module_available || phase === "running"}>
              {phase === "running" ? "Analyzing…" : "Analyze"}
            </button>
          </div>
          <TypeHint ident={ident} failed={failed} value={value} />
        </form>
        {phase === "running" && <ScanProgress step={step} />}
      </section>

      {error && <ErrorState title="The scan could not complete" message={error.message} onRetry={() => run(value.trim())} />}
      {report && <Report report={report} />}
    </div>
  );
}

function TypeHint({ ident, failed, value }) {
  if (failed) return <p className="scan-hint is-error">{failed}</p>;
  if (!ident) {
    const looksLikeText = /\s/.test(value || "") && (value || "").trim().split(/\s+/).length >= 10;
    if (looksLikeText) {
      return (
        <p className="scan-hint">This looks like free text rather than an indicator.{" "}
          <Link to={`/text?q=${encodeURIComponent(value.trim())}`} className="text-link">Open it in the Text Analyzer</Link>.
        </p>
      );
    }
    return <p className="scan-hint">Links, hashes, IPs, domains and CVEs run end-to-end. Passwords belong in Account Security; long writing belongs in the Text Analyzer.</p>;
  }
  if (ident.indicator_type === "unknown") {
    return <p className="scan-hint is-warn">{ident.notes[0] || "Not recognized."}</p>;
  }
  if (ident.module_available) {
    return <p className="scan-hint is-ok">Detected {TYPE_LABELS[ident.indicator_type]}. {ident.module_label} will analyze it now.</p>;
  }
  return <p className="scan-hint is-warn">Detected {TYPE_LABELS[ident.indicator_type]}, but {ident.module_label} isn&apos;t available yet (phase {ident.module_phase}).</p>;
}
