import { confidenceLabel, levelClass } from "../format.js";

export function RiskBadge({ level, score }) {
  return (
    <span className={`risk-badge ${levelClass(level)}`}>
      <span className="risk-dot" aria-hidden="true" />
      {level}
      {score !== undefined && <span className="risk-badge-score">{score}</span>}
    </span>
  );
}

export function RiskScore({ score, level, size = 120 }) {
  const stroke = Math.max(6, size / 12);
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className={`risk-score ${levelClass(level)}`} style={{ width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Risk score ${score} out of 100, ${level}`}>
        <circle cx={size / 2} cy={size / 2} r={r} className="gauge-track" strokeWidth={stroke} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} className="gauge-fill" strokeWidth={stroke} fill="none" strokeLinecap="round"
          strokeDasharray={`${c * pct} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="gauge-number" fontSize={size * 0.3}>{score}</text>
      </svg>
      <span className="risk-score-level">{level} risk</span>
    </div>
  );
}

export function ConfidenceIndicator({ value }) {
  const label = confidenceLabel(value);
  const filled = label === "High" ? 3 : label === "Moderate" ? 2 : 1;
  return (
    <span className="confidence" title={`Confidence ${Math.round(value * 100)}%`}>
      <span className="confidence-bars" aria-hidden="true">
        {[1, 2, 3].map((n) => <i key={n} className={n <= filled ? "on" : ""} />)}
      </span>
      {label} confidence
    </span>
  );
}
