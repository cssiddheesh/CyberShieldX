import { TYPE_LABELS, formatDateTime } from "../format.js";
import { Link } from "../router.jsx";
import { ConfidenceIndicator, RiskBadge } from "../components/Risk.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { useApi } from "../hooks.js";

export default function Reports() {
  const { data, error, loading, reload } = useApi("/scans?limit=100");

  if (loading && !data) return <LoadingState label="Loading reports" />;
  if (error) return <ErrorState title="Reports could not load" message={error.message} onRetry={reload} />;
  if (!data.total) {
    return (
      <section className="panel">
        <h2 className="panel-title">Reports</h2>
        <p className="muted">No scans yet. Run any analyzer and its report will appear here as JSON and PDF.</p>
        <p><Link to="/analyze" className="btn">Open the Universal Analyzer</Link></p>
      </section>
    );
  }

  const download = (scan, format) => {
    const url = format === "pdf" ? `/api/reports/${encodeURIComponent(scan.id)}.pdf`
      : `/api/reports/${encodeURIComponent(scan.id)}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = `${scan.id}.${format === "pdf" ? "pdf" : "json"}`;
    if (format === "pdf") a.removeAttribute("download");
    a.click();
  };

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">Reports ({data.total})</h2>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>When</th><th>Indicator</th><th>Type</th><th>Risk</th><th>Confidence</th><th>Exports</th></tr>
            </thead>
            <tbody>
              {data.items.map((scan) => (
                <tr key={scan.id}>
                  <td className="nowrap">{formatDateTime(scan.created_at)}</td>
                  <td className="mono truncate" title={scan.indicator}>
                    <Link to={`/history/${encodeURIComponent(scan.id)}`} className="text-link mono">{scan.indicator}</Link>
                    {scan.is_demo && <span className="chip chip-demo">Demo data</span>}
                  </td>
                  <td>{TYPE_LABELS[scan.indicator_type] || scan.indicator_type}</td>
                  <td><RiskBadge level={scan.risk_level} score={scan.risk_score} /></td>
                  <td><ConfidenceIndicator value={scan.confidence} /></td>
                  <td className="nowrap">
                    <button className="btn btn-quiet" onClick={() => download(scan, "json")}>JSON</button>{" "}
                    <button className="btn btn-quiet" onClick={() => download(scan, "pdf")}>PDF</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
