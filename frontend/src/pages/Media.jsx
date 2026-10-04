import { useState } from "react";
import { api } from "../api.js";
import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { ScanProgress } from "./Phishing.jsx";

const MAX_BYTES = 25 * 1024 * 1024;

export default function Media() {
  const [state, setState] = useState({ phase: "idle", step: 0, report: null, error: null });

  const upload = async (file) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setState({ phase: "done", step: 0, report: null, error: new Error("That image is larger than 25 MB.") });
      return;
    }
    setState({ phase: "running", step: 1, report: null, error: null });
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const report = await api.upload("/scans/media", form);
      setState({ phase: "done", step: 4, report, error: null });
    } catch (error) {
      setState({ phase: "done", step: 0, report: null, error });
    }
  };

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Inspect an image</h2>
        <p className="muted">Headers, metadata and compression are examined locally. The image is never run as code.</p>
        <form className="scan-form" onSubmit={(e) => e.preventDefault()}>
          <label className="scan-label" htmlFor="media-upload">Choose a PNG, JPEG, GIF, BMP or WebP file</label>
          <input id="media-upload" type="file" accept=".png,.jpg,.jpeg,.gif,.bmp,.webp"
            onChange={(e) => upload(e.target.files[0])} disabled={state.phase === "running"} />
        </form>
        {state.phase === "running" && <ScanProgress step={state.step} />}
      </section>

      {state.phase === "running" && !state.report && <LoadingState label="Parsing image" />}
      {state.error && <ErrorState title="The image could not be analyzed" message={state.error.message} />}
      {state.report && <Report report={state.report} />}
    </div>
  );
}
