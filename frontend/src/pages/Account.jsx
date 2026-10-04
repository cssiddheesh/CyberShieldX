import { useState } from "react";
import { api } from "../api.js";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { ScanProgress } from "./Phishing.jsx";

export default function Account() {
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const [state, setState] = useState({ phase: "idle", step: 0, report: null, error: null });

  const run = async (password) => {
    setState({ phase: "running", step: 1, report: null, error: null });
    const timer = setTimeout(() => setState((s) => ({ ...s, step: 2 })), 300);
    try {
      const report = await api.post("/scans/password", { password }, { timeout: 60000 });
      clearTimeout(timer);
      setState({ phase: "done", step: 4, report, error: null });
    } catch (error) {
      clearTimeout(timer);
      setState({ phase: "done", step: 0, report: null, error });
    }
  };

  const submit = (e) => {
    e.preventDefault();
    if (value) run(value);
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Check a password</h2>
        <form className="scan-form" onSubmit={submit}>
          <div className="scan-field">
            <input type={show ? "text" : "password"} value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="Type a password to test its strength and exposure" maxLength={512}
              autoComplete="new-password" spellCheck="false" aria-label="Password to check" />
            <button className="btn btn-quiet" type="button" onClick={() => setShow((s) => !s)}>
              {show ? "Hide" : "Show"}
            </button>
            <button className="btn btn-primary" type="submit" disabled={state.phase === "running" || !value}>
              {state.phase === "running" ? "Checking…" : "Check"}
            </button>
          </div>
          <p className="privacy-note">Private by design: strength is judged on this computer, only the first 5 characters
            of the password&apos;s hash ever leave it, and the password itself is never stored.</p>
        </form>
        {state.phase === "running" && <ScanProgress step={state.step} />}
      </section>

      {state.phase === "running" && !state.report && <LoadingState label="Checking password" />}
      {state.error && <ErrorState title="The check could not complete" message={state.error.message} onRetry={() => run(value)} />}
      {state.report && <Report report={state.report} />}
    </div>
  );
}
