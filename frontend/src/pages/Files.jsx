import { useState } from "react";
import { api } from "../api.js";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { ScanProgress } from "./Phishing.jsx";

const MAX_BYTES = 25 * 1024 * 1024;

export default function Files() {
  const [hash, setHash] = useState("");
  const [state, setState] = useState({ phase: "idle", step: 0, report: null, error: null });

  const finish = (report) => setState({ phase: "done", step: 4, report, error: null });
  const fail = (error) => setState({ phase: "done", step: 0, report: null, error });

  const scanHash = async (value) => {
    setState({ phase: "running", step: 2, report: null, error: null });
    try {
      finish(await api.post("/scans", { input: value }, { timeout: 60000 }));
    } catch (error) {
      fail(error);
    }
  };

  const upload = async (file) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      fail(new Error(`That file is larger than ${MAX_BYTES / 1024 / 1024} MB.`));
      return;
    }
    setState({ phase: "running", step: 1, report: null, error: null });
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      finish(await api.upload("/scans/file", form));
    } catch (error) {
      fail(error);
    }
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Inspect a file or hash</h2>
        <form className="scan-form" onSubmit={(e) => { e.preventDefault(); if (hash.trim()) scanHash(hash.trim()); }}>
          <div className="scan-field">
            <input type="text" value={hash} onChange={(e) => setHash(e.target.value)}
              placeholder="Paste an MD5, SHA-1 or SHA-256 hash" maxLength={128}
              autoComplete="off" spellCheck="false" aria-label="File hash to look up" />
            <button className="btn btn-primary" type="submit" disabled={state.phase === "running" || !hash.trim()}>
              {state.phase === "running" ? "Analyzing…" : "Look up"}
            </button>
          </div>
        </form>
        <form className="scan-form" onSubmit={(e) => e.preventDefault()}>
          <label className="scan-label" htmlFor="file-upload">Or choose a file from this computer (hashed locally, never run, never stored)</label>
          <input id="file-upload" type="file" onChange={(e) => upload(e.target.files[0])}
            disabled={state.phase === "running"} />
        </form>
        {state.phase === "running" && <ScanProgress step={state.step} />}
      </section>

      {state.phase === "running" && !state.report && <LoadingState label="Analyzing file" />}
      {state.error && <ErrorState title="The scan could not complete" message={state.error.message}
        onRetry={() => hash.trim() && scanHash(hash.trim())} />}
      {state.report && <Report report={state.report} />}
    </div>
  );
}
