import { useState } from "react";
import { api } from "../api.js";
import { useAppData } from "../hooks.js";

export default function Settings() {
  const { config, refreshConfig } = useAppData();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [key, setKey] = useState("");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [aiMsg, setAiMsg] = useState(null);

  const toggle = async () => {
    setBusy(true); setError(null);
    try { await api.put("/settings", { demo_mode: !config.demo_mode }); await refreshConfig(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const saveAi = async (e) => {
    e.preventDefault();
    setBusy(true); setAiMsg(null);
    try {
      const body = {};
      if (key) body.api_key = key;
      if (model.trim()) body.model = model.trim();
      if (baseUrl.trim()) body.base_url = baseUrl.trim();
      await api.put("/settings/ai", body);
      setKey("");
      await refreshConfig();
      setAiMsg("Saved. The key is stored on this computer only and never shown again.");
    } catch (err) { setAiMsg(err.message); }
    finally { setBusy(false); }
  };

  const clearKey = async () => {
    setBusy(true); setAiMsg(null);
    try { await api.put("/settings/ai", { api_key: "" }); await refreshConfig(); setAiMsg("AI key removed."); }
    catch (err) { setAiMsg(err.message); }
    finally { setBusy(false); }
  };

  return (
    <div className="stack narrow">
      <section className="panel">
        <div className="setting-row">
          <div>
            <h2 className="panel-title">Demo Mode</h2>
            <p className="muted">
              Labels the whole interface as DEMO MODE. It is meant for the exhibition, so everything shown can be
              told apart from live results. Prepared demonstration data is added together with the first analyzers.
            </p>
          </div>
          <button role="switch" aria-checked={config.demo_mode} className={`switch${config.demo_mode ? " is-on" : ""}`}
            onClick={toggle} disabled={busy} aria-label="Demo Mode">
            <span />
          </button>
        </div>
        {error && <p className="inline-error" role="alert">{error}</p>}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">AI-enhanced reports</h2>
          {config.ai?.configured
            ? <span className="chip chip-ok">Key set</span>
            : <span className="chip">Not set</span>}
        </div>
        <p className="muted">
          Paste an AI model key (OpenAI, any OpenAI-compatible endpoint, or a local server like
          Ollama) and every report automatically gains a plain-prose AI explanation section. The model only ever sees the
          scan's evidence summary — never passwords, never your key. Optional: everything works without it.
        </p>
        <form className="scan-form" onSubmit={saveAi}>
          <label className="scan-label" htmlFor="ai-key">API key</label>
          <div className="scan-field">
            <input id="ai-key" type="password" value={key} onChange={(e) => setKey(e.target.value)}
              placeholder={config.ai?.configured ? "Key is set (enter a new one to replace it)" : "sk-…"}
              autoComplete="off" spellCheck="false" />
          </div>
          <label className="scan-label" htmlFor="ai-model">Model (current: {config.ai?.model})</label>
          <div className="scan-field">
            <input id="ai-model" type="text" value={model} onChange={(e) => setModel(e.target.value)}
              placeholder="gpt-4o-mini" autoComplete="off" spellCheck="false" />
          </div>
          <label className="scan-label" htmlFor="ai-url">API base URL (current: {config.ai?.base_url})</label>
          <div className="scan-field">
            <input id="ai-url" type="text" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://api.openai.com/v1" autoComplete="off" spellCheck="false" />
          </div>
          <div className="form-row">
            <button className="btn btn-primary" type="submit" disabled={busy}>Save AI settings</button>
            {config.ai?.configured && <button className="btn btn-quiet" type="button" onClick={clearKey} disabled={busy}>Remove key</button>}
          </div>
          {aiMsg && <p className="scan-hint" aria-live="polite">{aiMsg}</p>}
        </form>
      </section>

      <section className="panel">
        <h2 className="panel-title">Limits</h2>
        <dl className="meta-grid wide">
          <div><dt>Largest file you can upload</dt><dd>{config.limits.max_upload_mb} MB</dd></div>
          <div><dt>Wait time for each provider</dt><dd>{config.limits.http_timeout_seconds} seconds</dd></div>
          <div><dt>Retries after a failure</dt><dd>{config.limits.http_retries}</dd></div>
          <div><dt>Requests per minute</dt><dd>{config.limits.rate_limit_per_minute}</dd></div>
        </dl>
        <p className="muted">Limits come from your .env file. Restart CyberShield X after changing it.</p>
      </section>

      <section className="panel">
        <h2 className="panel-title">Privacy</h2>
        <p className="muted">{config.external_data_notice}</p>
        <p className="muted">CyberShield X {config.version}</p>
      </section>
    </div>
  );
}
