import { TYPE_LABELS, formatDateTime } from "../format.js";
import { Link } from "../router.jsx";
import { ConfidenceIndicator, RiskBadge } from "./Risk.jsx";
import { EmptyState } from "./States.jsx";

export function RecentScans({ scans, compact = false }) {
  if (!scans.length) {
    return (
      <EmptyState icon="history" title="No saved scans yet"
        action={<Link to="/analyze" className="btn">Open the Universal Analyzer</Link>}>
        Every analysis you run is saved here so you can review it later.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>When</th><th>Indicator</th><th>Type</th><th>Risk</th>
            {!compact && <th>Confidence</th>}
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="nowrap">{formatDateTime(scan.created_at)}</td>
              <td className="mono truncate" title={scan.indicator}>
                <Link to={`/history/${encodeURIComponent(scan.id)}`} className="text-link mono">{scan.indicator}</Link>
                {scan.is_demo && <span className="chip chip-demo">Demo data</span>}
              </td>
              <td>{TYPE_LABELS[scan.indicator_type] || scan.indicator_type}</td>
              <td><RiskBadge level={scan.risk_level} score={scan.risk_score} /></td>
              {!compact && <td><ConfidenceIndicator value={scan.confidence} /></td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
