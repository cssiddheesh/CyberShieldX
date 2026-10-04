import { useState } from "react";
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
  const query = new URLSearchParams({ limit: PAGE, offset });
  if (risk) query.set("risk", risk);
  if (type) query.set("type", type);
  const { data, error, loading, reload } = useApi(`/scans?${query}`);

  const change = (setter) => (e) => { setter(e.target.value); setOffset(0); };
  const filtered = Boolean(risk || type);

  return (
    <div className="stack">
      <section className="panel">
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
        {loading && !data ? <LoadingState label="Loading scans" /> :
          error ? <ErrorState title="History could not load" message={error.message} onRetry={reload} /> :
          data.total === 0 && filtered ? <p className="muted pad">No saved scans match these filters.</p> :
          <>
            <RecentScans scans={data.items} />
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
