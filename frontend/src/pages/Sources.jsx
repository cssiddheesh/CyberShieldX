import { useState } from "react";
import { api } from "../api.js";
import Icon from "../components/Icon.jsx";
import { StateChip } from "../components/Sources.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { TYPE_LABELS } from "../format.js";
import { useApi } from "../hooks.js";

function SourceCard({ source, onToggle, busy }) {
  const off = source.user_disabled;
  return (
    <article className="panel source-card">
      <div className="source-card-head">
        <div>
          <h3>{source.name}</h3>
          <p className="muted">{source.description}</p>
        </div>
        <StateChip state={source.state} reason={source.reason} />
      </div>
      <p className="source-detail">{source.detail}</p>
      <dl className="meta-grid">
        <div><dt>Checks</dt><dd>{source.indicator_types.map((t) => TYPE_LABELS[t] || t).join(", ")}</dd></div>
        <div><dt>API key</dt><dd>{source.requires_key ? (source.key_set ? "Set in .env" : `Not set (${source.env_var})`) : "Not needed"}</dd></div>
        <div><dt>Internal weight</dt><dd>{Math.round(source.default_reliability * 100)}%</dd></div>
      </dl>
      <p className="privacy-note"><Icon name="shield" size={14} /> {source.data_sent}</p>
      <div className="source-card-foot">
        <a className="text-link" href={source.homepage} target="_blank" rel="noopener noreferrer">
          Provider website <Icon name="external" size={13} />
        </a>
        {source.implemented && (
          <button className="btn btn-quiet" disabled={busy} onClick={() => onToggle(source.key, off)}>
            {off ? "Turn on" : "Turn off"}
          </button>
        )}
      </div>
    </article>
  );
}

export default function Sources() {
  const { data, error, loading, reload } = useApi("/sources");
  const [busy, setBusy] = useState(null);
  const [actionError, setActionError] = useState(null);

  if (loading && !data) return <LoadingState label="Loading sources" />;
  if (error) return <ErrorState title="Sources could not load" message={error.message} onRetry={reload} />;

  const toggle = async (key, enable) => {
    setBusy(key); setActionError(null);
    try { await api.put(`/sources/${key}`, { enabled: enable }); reload(); }
    catch (e) { setActionError(e.message); }
    finally { setBusy(null); }
  };

  const count = (fn) => data.items.filter(fn).length;
  const summary = [
    [count((s) => s.reason === "unchecked" || s.state === "AVAILABLE"), "ready"],
    [count((s) => s.reason === "no_key"), "need an API key"],
    [count((s) => s.reason === "not_built"), "not built yet"],
    [count((s) => s.reason === "user_disabled"), "turned off"],
  ].filter(([n]) => n > 0);
  return (
    <div className="stack">
      <section className="panel intro">
        <p>
          CyberShield X combines its own local analysis with these optional public intelligence sources. A source that
          is not configured is skipped and is never counted as "no threat found". The internal weight is how much
          CyberShield X trusts a source when combining evidence. It is not a claim that the source is always right.
        </p>
        <p className="muted">
          {summary.map(([n, label]) => `${n} ${label}`).join(", ")}
        </p>
      </section>
      {actionError && <p className="inline-error" role="alert">{actionError}</p>}
      <div className="card-grid">
        {data.items.map((s) => <SourceCard key={s.key} source={s} onToggle={toggle} busy={busy === s.key} />)}
      </div>
    </div>
  );
}
