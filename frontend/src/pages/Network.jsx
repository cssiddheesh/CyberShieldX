import { useState } from "react";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { ScanProgress, useScan } from "./Phishing.jsx";

export default function Network({ preset = "" }) {
  const [value, setValue] = useState(preset);
  const [{ phase, step, report, error }, run] = useScan();

  const submit = (e) => {
    e.preventDefault();
    if (value.trim()) run(value.trim());
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Investigate an IP address or domain</h2>
        <form className="scan-form" onSubmit={submit}>
          <div className="scan-field">
            <input type="text" value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="e.g. 8.8.8.8 or example.com" maxLength={253}
              autoComplete="off" spellCheck="false" aria-label="IP address or domain" />
            <button className="btn btn-primary" type="submit" disabled={phase === "running" || !value.trim()}>
              {phase === "running" ? "Investigating…" : "Investigate"}
            </button>
          </div>
          <p className="fine-print">Local classification runs on this computer. When an external source is used, the address may be sent to that provider.</p>
        </form>
        {phase === "running" && <ScanProgress step={step} />}
      </section>

      {phase === "running" && !report && <LoadingState label="Gathering intelligence" />}
      {error && <ErrorState title="The scan could not complete" message={error.message} onRetry={() => run(value.trim())} />}
      {report && <Report report={report} />}
    </div>
  );
}
