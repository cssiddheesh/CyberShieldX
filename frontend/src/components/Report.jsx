import { useEffect, useState } from "react";
import { api } from "../api.js";
import { STATE_INFO, levelClass } from "../format.js";
import { useAppData } from "../hooks.js";
import { Link } from "../router.jsx";
import { ConfidenceIndicator, RiskBadge, RiskScore } from "./Risk.jsx";

const SEV_TONE = { critical: "chip-bad", high: "chip-bad", medium: "chip-warn", low: "", info: "" };
const ORIGIN_LABEL = {
  LIVE_RESULT: "Live result", CACHED_RESULT: "Cached result", LOCAL_ANALYSIS: "Local analysis",
  DEMO_DATA: "Demonstration data", NOT_CONFIGURED: "Not configured", PROVIDER_ERROR: "Provider error",
};

export function OriginChip({ origin, demo }) {
  if (demo) return <span className="chip chip-demo">DEMONSTRATION DATA</span>;
  const tone = origin === "LIVE_RESULT" ? "chip-ok" : origin === "PROVIDER_ERROR" ? "chip-bad" : "";
  return <span className={`chip ${tone}`}>{ORIGIN_LABEL[origin] || origin}</span>;
}

function ScoreBar({ contributions }) {
  const total = contributions.reduce((n, c) => n + Math.max(0, c.points), 0);
  return (
    <div>
      <div className="stack-bar" role="img" aria-label="Risk score composition">
        {contributions.filter((c) => c.points > 0).map((c, i) => (
          <span key={i} className={`stack-seg ${levelClass(c.source === "Risk Engine" || c.source === "Correlation Engine" ? "moderate" : "high")}`}
            style={{ flexGrow: Math.max(1, c.points) }} title={`${c.source}: +${c.points}`} />
        ))}
      </div>
      <ul className="contrib-list">
        {contributions.map((c, i) => (
          <li key={i}>
            <strong>{c.source}</strong> <span className={c.points < 0 ? "is-ok" : ""}>{c.points >= 0 ? `+${c.points}` : c.points}</span>
            {" — "}{c.detail}
          </li>
        ))}
      </ul>
      {total === 0 && <p className="muted">No risk points. The baseline score of 5 still applies.</p>}
    </div>
  );
}

export default function Report({ report }) {
  const { config } = useAppData();
  const [enhanced, setEnhanced] = useState(report.ai_enhanced || null);
  const [enhancing, setEnhancing] = useState(false);
  const [enhanceError, setEnhanceError] = useState(null);
  const local = report.local_analysis || {};
  const facts = local.facts || null;
  const isUrl = report.module === "phishing";

  const enhance = async () => {
    setEnhancing(true);
    setEnhanceError(null);
    try {
      const data = await api.post(`/scans/${encodeURIComponent(report.scan_id)}/ai`, {}, { timeout: 90000 });
      setEnhanced(data);
    } catch (e) {
      setEnhanceError(e.message);
    } finally {
      setEnhancing(false);
    }
  };

  useEffect(() => {
    if (!enhanced && !enhancing && !enhanceError && config?.ai?.configured && report.scan_id) {
      enhance();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report.scan_id, enhanced, config?.ai?.configured]);
  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.scan_id || "cybershield-report"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">Target</h2>
          <OriginChip origin={report.origins?.[0]} demo={report.is_demo} />
        </div>
        <p className="mono break">{report.target}</p>
        {isUrl ? (
          <dl className="meta-grid">
            <div><dt>Domain</dt><dd className="mono">{local.domain || "—"}</dd></div>
            <div><dt>Protocol</dt><dd className="mono">{local.protocol || "—"}</dd></div>
            <div><dt>Analyzed</dt><dd>{report.analysis_time ? new Date(report.analysis_time).toLocaleString() : "—"}</dd></div>
            <div><dt>Scan ID</dt><dd className="mono">{report.scan_id || "—"}</dd></div>
            <div><dt>Link length</dt><dd>{local.url_length ?? "—"} characters</dd></div>
            <div><dt>Randomness (entropy)</dt><dd>{local.entropy ?? "—"} bits/char</dd></div>
          </dl>
        ) : (
          <dl className="meta-grid">
            {facts && Object.entries(facts).map(([key, val]) => (
              <div key={key}><dt>{key.replace(/_/g, " ")}</dt><dd className="mono">{String(val)}</dd></div>
            ))}
            <div><dt>Analyzed</dt><dd>{report.analysis_time ? new Date(report.analysis_time).toLocaleString() : "—"}</dd></div>
            <div><dt>Scan ID</dt><dd className="mono">{report.scan_id || "—"}</dd></div>
          </dl>
        )}
        {local.was_defanged && <p className="scan-hint is-warn">The link was shared in defanged form and restored before analysis.</p>}
        {(local.notes || []).map((note, i) => <p key={i} className="scan-hint">{note}</p>)}
        {local.plain_language && <p><strong>In plain language:</strong> {local.plain_language}</p>}
      </section>

      <section className="panel">
        <h2 className="panel-title">Risk assessment</h2>
        <div className="risk-row">
          <RiskScore score={report.risk_score} level={report.overall_risk} />
          <div className="risk-meta">
            <p><RiskBadge level={report.overall_risk} score={report.risk_score} /> <ConfidenceIndicator value={report.confidence} /></p>
            <p className="verdict">{report.verdict_label}</p>
            <p className="fine-print">Risk scores are internal CyberShield X assessments, not official industry ratings.</p>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">AI Security Analyst</h2>
          {report.is_demo
            ? <span className="chip chip-demo">DEMONSTRATION DATA</span>
            : <span className="chip chip-ok">Grounded in evidence</span>}
        </div>
        {report.ai_analysis ? (
          <div className="stack">
            <p>{report.ai_analysis.executive_summary}</p>
            <div>
              <h3 className="ai-heading">Observed — what the evidence shows</h3>
              <ul className="finding-list">{report.ai_analysis.observed.map((o, i) => <li key={i}>{o}</li>)}</ul>
            </div>
            <div>
              <h3 className="ai-heading">Assessment — what it means</h3>
              <p>{report.ai_analysis.assessment}</p>
            </div>
            <div>
              <h3 className="ai-heading">Uncertainty — what is not known</h3>
              <ul className="finding-list">{report.ai_analysis.uncertainty.map((u, i) => <li key={i} className="muted">{u.text}</li>)}</ul>
            </div>
            <p className="fine-print">The analyst only restates cited evidence below — it cannot invent sources or findings. Every key finding links to its evidence item.</p>
          </div>
        ) : (
          <p className="muted">This scan was saved before the AI analyst existed, so only the scored report is available.</p>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">AI explanation</h2>
        </div>
        {enhanced ? (
          <div className="stack">
            <p>{enhanced.plain_summary}</p>
            <div>
              <h3 className="ai-heading">What matters most</h3>
              <ul className="finding-list">{enhanced.what_matters.map((w, i) => <li key={i}>{w}</li>)}</ul>
            </div>
            <div>
              <h3 className="ai-heading">Next steps</h3>
              <ul className="finding-list">{enhanced.next_steps.map((n, i) => <li key={i}>{n}</li>)}</ul>
            </div>
            <div>
              <h3 className="ai-heading">Blind spots</h3>
              <ul className="finding-list">{enhanced.blind_spots.map((b, i) => <li key={i} className="muted">{b}</li>)}</ul>
            </div>
          </div>
        ) : config?.ai?.configured ? (
          <div>
            {enhanceError
              ? <p className="muted">The AI explanation could not load. <button className="text-link" onClick={enhance}>Try again</button></p>
              : <p className="muted">Preparing the AI explanation…</p>}
          </div>
        ) : (
          <p className="muted">Add an AI model key in <Link to="/settings" className="text-link">Settings</Link> to enable plainer-prose explanations of this report.</p>
        )}
      </section>

      <section className="panel">
        <h2 className="panel-title">Security assessment</h2>
        <p>{report.executive_summary}</p>
        <p className="fine-print">This assessment is grounded only in the evidence below. It never states certainty from heuristics alone.</p>
      </section>

      <section className="panel">
        <h2 className="panel-title">Key findings ({(report.findings || []).length})</h2>
        {!report.findings?.length ? <p className="muted">No suspicious findings. This does not prove safety.</p> :
          <ul className="finding-list">
            {report.findings.map((f, i) => (
              <li key={i} className="finding">
                <span className={`chip ${SEV_TONE[f.severity] || ""}`}>{f.severity}</span>
                <div><strong>{f.title}</strong><p className="muted">{f.source} · confidence {Math.round(f.confidence * 100)}%</p></div>
              </li>
            ))}
          </ul>}
      </section>

      <section className="panel">
        <h2 className="panel-title">
          {isUrl ? `Local link analysis (${(local.indicators || []).length} signals)`
            : `Local analysis (${(local.indicators || []).length} signals)`}
        </h2>
        {!local.indicators?.length ? <p className="muted">{isUrl ? "The link parses cleanly: no obfuscation, impersonation or redirect patterns detected locally." : "Nothing suspicious stood out in local analysis. Intelligence results below add the next layer."}</p> :
          <ul className="finding-list">
            {local.indicators.map((ind) => (
              <li key={ind.id} className="finding">
                <span className={`chip ${SEV_TONE[ind.severity] || ""}`}>{ind.severity}</span>
                <div><strong>{ind.title}</strong><p className="muted">{ind.detail}</p></div>
              </li>
            ))}
          </ul>}
      </section>

      <section className="panel">
        <h2 className="panel-title">Evidence ({(report.evidence || []).length})</h2>
        <p className="muted">{report.correlation_explanation}</p>
        <div className="stack">
          {(report.evidence || []).map((e, i) => (
            <details key={i} className="evidence">
              <summary>
                <span className={`chip ${SEV_TONE[e.severity] || ""}`}>{e.severity}</span>
                <strong>{e.finding}</strong>
                <span className="muted"> — {e.source}</span>
              </summary>
              <dl className="meta-grid wide">
                <div><dt>Source</dt><dd>{e.source} ({e.source_type})</dd></div>
                <div><dt>Origin</dt><dd>{ORIGIN_LABEL[e.origin] || e.origin}</dd></div>
                <div><dt>Confidence</dt><dd>{Math.round(e.confidence * 100)}%</dd></div>
                <div><dt>Status</dt><dd>{e.status}</dd></div>
              </dl>
              <p>{e.evidence}</p>
              {e.reference && <p><a className="text-link" href={e.reference} target="_blank" rel="noreferrer">{e.reference}</a></p>}
            </details>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2 className="panel-title">Why this score</h2>
        <ScoreBar contributions={report.score_contributions || []} />
      </section>

      <section className="panel">
        <h2 className="panel-title">Sources consulted ({(report.sources_consulted || []).length})</h2>
        <ul className="source-list">
          {(report.sources_consulted || []).map((s) => (
            <li key={s.key} className="source-row">
              <span>{s.name}</span>
              <span className={`chip ${s.state === "AVAILABLE" ? "chip-ok" : s.state === "NOT_CONFIGURED" ? "chip-warn" : "chip-bad"}`}>
                {STATE_INFO[s.state]?.label || s.state}
              </span>
              <span className="muted">{s.message}</span>
            </li>
          ))}
        </ul>
        {!report.sources_consulted?.length && (
          <p className="muted">No external sources are configured yet. This assessment uses local analysis only — see <Link to="/sources" className="text-link">Intelligence Sources</Link> to add API keys.</p>
        )}
      </section>

      <section className="two-col">
        <div className="panel">
          <h2 className="panel-title">Recommended actions</h2>
          <ul className="finding-list">{(report.recommendations || []).map((r, i) => <li key={i}>{r}</li>)}</ul>
        </div>
        <div className="panel">
          <h2 className="panel-title">Limitations</h2>
          <ul className="finding-list">{(report.limitations || []).map((l, i) => <li key={i} className="muted">{l}</li>)}</ul>
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">Report</h2>
          <button className="btn btn-quiet" onClick={downloadJson}>Download JSON</button>
        </div>
        <p className="fine-print">Saved to Scan History automatically. Reopen it any time from the history list.</p>
      </section>
    </div>
  );
}
