import { useState } from "react";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { ScanProgress, useScan } from "./Phishing.jsx";

export default function Vulns() {
  const [value, setValue] = useState("");
  const [{ phase, step, report, error }, run] = useScan();

  const submit = (e) => {
    e.preventDefault();
    if (value.trim()) run(value.trim().toUpperCase());
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Look up a CVE</h2>
        <form className="scan-form" onSubmit={submit}>
          <div className="scan-field">
            <input type="text" value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="e.g. CVE-2021-44228" maxLength={32}
              autoComplete="off" spellCheck="false" aria-label="CVE identifier" />
            <button className="btn btn-primary" type="submit" disabled={phase === "running" || !value.trim()}>
              {phase === "running" ? "Looking up…" : "Look up"}
            </button>
          </div>
          <p className="fine-print">Severity explained in plain language. CyberShield X never provides exploit instructions.</p>
        </form>
        {phase === "running" && <ScanProgress step={step} />}
      </section>

      {phase === "running" && !report && <LoadingState label="Fetching vulnerability record" />}
      {error && <ErrorState title="The lookup could not complete" message={error.message} onRetry={() => run(value.trim().toUpperCase())} />}
      {report && <Report report={report} />}
    </div>
  );
}
