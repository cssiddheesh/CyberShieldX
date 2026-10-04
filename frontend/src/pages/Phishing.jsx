import { useEffect, useState } from "react";
import { api } from "../api.js";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { useRouter } from "../router.jsx";

const STEPS = ["Input validated", "Local analysis completed", "Querying threat intelligence…", "Correlating evidence", "Generating assessment"];

export function useScan() {
  const [state, setState] = useState({ phase: "idle", step: 0, report: null, error: null });
  const run = async (input) => {
    setState({ phase: "running", step: 0, report: null, error: null });
    const advance = (step) => setState((s) => ({ ...s, step }));
    // Local steps complete immediately; the single request covers intel + correlation.
    const timers = [setTimeout(() => advance(1), 150), setTimeout(() => advance(2), 350)];
    try {
      const report = await api.post("/scans", { input }, { timeout: 60000 });
      advance(4);
      setState({ phase: "done", step: 4, report, error: null });
      return report;
    } catch (error) {
      setState({ phase: "done", step: 0, report: null, error });
      return null;
    } finally {
      timers.forEach(clearTimeout);
    }
  };
  return [state, run];
}

export function ScanProgress({ step }) {
  return (
    <ol className="scan-steps" aria-live="polite">
      {STEPS.map((label, i) => (
        <li key={label} className={i < step ? "is-done" : i === step ? "is-active" : ""}>
          <span aria-hidden="true">{i < step ? "✓ " : i === step ? "⟳ " : "○ "}</span>{label}
        </li>
      ))}
    </ol>
  );
}

export function initialFromQuery() {
  const params = new URLSearchParams(window.location.search);
  return params.get("q") || "";
}

export default function Phishing() {
  const { navigate } = useRouter();
  const [value, setValue] = useState(initialFromQuery);
  const [{ phase, step, report, error }, run] = useScan();

  useEffect(() => {
    const q = initialFromQuery();
    if (q) {
      setValue(q);
      run(q);
      navigate("/phishing", { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = (e) => {
    e.preventDefault();
    if (value.trim()) run(value.trim());
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Check a link</h2>
        <form className="scan-form" onSubmit={submit}>
          <div className="scan-field">
            <input type="text" value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="Paste a link, even a defanged one like hxxps://evil[.]com" maxLength={2048}
              autoComplete="off" spellCheck="false" aria-label="Link to analyze" />
            <button className="btn btn-primary" type="submit" disabled={phase === "running" || !value.trim()}>
              {phase === "running" ? "Analyzing…" : "Analyze"}
            </button>
          </div>
          <p className="fine-print">Local analysis runs on this computer. When an external source is used, the link may be sent to that provider.</p>
        </form>
        {phase === "running" && <ScanProgress step={step} />}
      </section>

      {phase === "running" && !report && <LoadingState label="Analyzing link" />}
      {error && <ErrorState title="The scan could not complete" message={error.message} onRetry={() => run(value.trim())} />}
      {report && <Report report={report} />}
    </div>
  );
}
