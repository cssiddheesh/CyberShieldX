import { useEffect, useState } from "react";
import { api } from "../api.js";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";

export function initialTextFromQuery() {
  const params = new URLSearchParams(window.location.search);
  return params.get("q") || "";
}

export default function Text() {
  const [value, setValue] = useState(initialTextFromQuery);
  const [state, setState] = useState({ phase: "idle", report: null, error: null });

  useEffect(() => {
    const q = initialTextFromQuery();
    if (q.length > 40) {
      setValue(q);
      window.history.replaceState(null, "", "/text");
    }
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    if (!value.trim()) return;
    setState({ phase: "running", report: null, error: null });
    try {
      const report = await api.post("/scans/text", { text: value }, { timeout: 30000 });
      setState({ phase: "done", report, error: null });
    } catch (error) {
      setState({ phase: "done", report: null, error });
    }
  };

  const words = value.trim() ? value.trim().split(/\s+/).length : 0;

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Analyze writing style</h2>
        <p className="muted">Paste an article, message or essay. Statistics estimate how AI-like it reads — never who wrote it.</p>
        <form className="scan-form" onSubmit={submit}>
          <textarea value={value} onChange={(e) => setValue(e.target.value)} rows={8} maxLength={20000}
            placeholder="Paste at least 40 words for a meaningful analysis…" aria-label="Text to analyze"
            className="text-input" />
          <div className="form-row">
            <span className="muted">{words} words{words > 0 && words < 40 ? " (need 40+)" : ""}</span>
            <button className="btn btn-primary" type="submit" disabled={state.phase === "running" || !value.trim()}>
              {state.phase === "running" ? "Analyzing…" : "Analyze"}
            </button>
          </div>
          <p className="fine-print">Analysis runs on this computer; your text is saved to scan history so you can reopen it.</p>
        </form>
      </section>

      {state.phase === "running" && <LoadingState label="Measuring style signals" />}
      {state.error && <ErrorState title="The analysis could not complete" message={state.error.message} onRetry={submit} />}
      {state.report && <Report report={state.report} />}
    </div>
  );
}
