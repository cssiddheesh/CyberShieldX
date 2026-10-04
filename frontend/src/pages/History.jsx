import { useState } from "react";
import { api } from "../api.js";
import { RecentScans } from "../components/Scans.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { RISK_LEVELS, TYPE_LABELS } from "../format.js";
import { useApi } from "../hooks.js";

const PAGE = 25;
const TYPES = ["url", "domain", "ipv4", "ipv6", "md5", "sha1", "sha256", "cve", "file", "password", "text", "image"];

export default function History() {
  const [risk, setRisk] = useState("");
  const [type, setType] = useState("");
  const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  const query = new URLSearchParams({ limit: PAGE, offset });
  if (risk) query.set("risk", risk);
  if (type) query.set("type", type);
  const { data, error, loading, reload } = useApi(`/scans?${query}`);

  const change = (setter) => (e) => { setter(e.target.value); setOffset(0); };
  const filtered = Boolean(risk || type);

  const deleteScan = async (scan) => {
    if (!window.confirm(`Delete the scan for "${scan.indicator}"? This cannot be undone.`)) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.delete(`/scans/${encodeURIComponent(scan.id)}`);
      if (data.items.length === 1 && offset > 0) setOffset(Math.max(0, offset - PAGE));
      reload();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const deleteAll = async () => {
    if (!window.confirm("Delete every saved scan and its reports? This cannot be undone.")) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.delete("/scans");
      setOffset(0);
      reload();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <section className="panel">
        <div className="history-toolbar">
          <div className="filters">
            <label>Risk level
              <select value={risk} onChange={change(setRisk)}>
                <option value="">All levels</option>
                {RISK_LEVELS.map((l) => <option key={l}>{l}</option>)}
              </select>
            </label>
            <label>Indicator type
              <select value={type} onChange={change(setType)}>
                <option value="">All types</option>
                {TYPES.map((t) => <option key={t} value={t}>{TYPE_LABELS[t]}</option>)}
              </select>
            </label>
            {filtered && <button className="btn btn-quiet" onClick={() => { setRisk(""); setType(""); setOffset(0); }}>Clear filters</button>}
          </div>
          <button className="btn btn-danger" type="button" disabled={busy || (data?.total === 0 && !filtered)}
            onClick={deleteAll}>Delete all scans</button>
        </div>
        {actionError && <p className="inline-error" role="alert">{actionError}</p>}
        {loading && !data ? <LoadingState label="Loading scans" /> :
          error ? <ErrorState title="History could not load" message={error.message} onRetry={reload} /> :
          data.total === 0 && filtered ? <p className="muted pad">No saved scans match these filters.</p> :
          <>
            <RecentScans scans={data.items} onDelete={deleteScan} deleting={busy} />
            {data.total > PAGE && (
              <div className="pager">
                <button className="btn btn-quiet" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
                <span className="muted">{offset + 1}-{Math.min(offset + PAGE, data.total)} of {data.total}</span>
                <button className="btn btn-quiet" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
              </div>
            )}
          </>}
      </section>
    </div>
  );
}
