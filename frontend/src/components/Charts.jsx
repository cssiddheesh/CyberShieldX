import { useState } from "react";
import { RISK_LEVELS, levelClass } from "../format.js";
import { useRouter } from "../router.jsx";
import { EmptyState } from "./States.jsx";

export function ThreatChart({ distribution, total }) {
  if (!total) {
    return <EmptyState icon="analyze" title="No scans yet">Results appear here once you analyze something.</EmptyState>;
  }
  return (
    <div className="threat-chart">
      <div className="stack-bar" role="img" aria-label={RISK_LEVELS.map((l) => `${l}: ${distribution[l] || 0}`).join(", ")}>
        {RISK_LEVELS.filter((l) => distribution[l]).map((level) => (
          <span key={level} className={`stack-seg ${levelClass(level)}`} style={{ flexGrow: distribution[level] }} />
        ))}
      </div>
      <ul className="legend-list">
        {RISK_LEVELS.slice().reverse().map((level) => (
          <li key={level}>
            <span className={`risk-dot ${levelClass(level)}`} aria-hidden="true" />
            <span className="legend-label">{level}</span>
            <span className="legend-count">{distribution[level] || 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const STATUS_TEXT = { ready: "Ready", partial: "Partly built", planned: "Not built yet" };

function polar(cx, cy, r, deg) {
  const a = (deg * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function arc(cx, cy, rOuter, rInner, a0, a1) {
  const [x0, y0] = polar(cx, cy, rOuter, a0);
  const [x1, y1] = polar(cx, cy, rOuter, a1);
  const [x2, y2] = polar(cx, cy, rInner, a1);
  const [x3, y3] = polar(cx, cy, rInner, a0);
  return `M${x0} ${y0} A${rOuter} ${rOuter} 0 0 1 ${x1} ${y1} L${x2} ${y2} A${rInner} ${rInner} 0 0 0 ${x3} ${y3}Z`;
}

/** The 360-degree coverage ring: eight dimensions, filled only as modules really work. */
export function CoverageRing({ dimensions }) {
  const { navigate } = useRouter();
  const [active, setActive] = useState(null);
  const step = 360 / dimensions.length;
  const ready = dimensions.filter((d) => d.status === "ready").length;

  return (
    <div className="ring-wrap">
      <svg viewBox="0 0 300 300" className="ring" role="group" aria-label="360 degree coverage">
        {dimensions.map((d, i) => {
          const start = -90 + i * step + 1.4;
          const end = -90 + (i + 1) * step - 1.4;
          return (
            <path key={d.key} d={arc(150, 150, 140, 98, start, end)}
              className={`ring-seg ring-${d.status}${active === d.key ? " is-active" : ""}`}
              tabIndex={0} role="link" aria-label={`${d.label}: ${STATUS_TEXT[d.status]}`}
              onMouseEnter={() => setActive(d.key)} onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(d.key)} onBlur={() => setActive(null)}
              onClick={() => navigate(d.path)}
              onKeyDown={(e) => e.key === "Enter" && navigate(d.path)} />
          );
        })}
        <text x="150" y="146" textAnchor="middle" className="ring-title">360°</text>
        <text x="150" y="172" textAnchor="middle" className="ring-sub">{ready} of {dimensions.length} areas ready</text>
      </svg>
      <ul className="ring-legend">
        {dimensions.map((d) => (
          <li key={d.key} className={active === d.key ? "is-active" : ""}
            onMouseEnter={() => setActive(d.key)} onMouseLeave={() => setActive(null)}>
            <span className={`ring-key ring-${d.status}`} aria-hidden="true" />
            <span className="ring-legend-text">
              <strong>{d.label}</strong>
              <span>{d.modules.length ? d.modules.join(", ") : "Platform"}</span>
            </span>
            <span className="ring-status">{STATUS_TEXT[d.status]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
