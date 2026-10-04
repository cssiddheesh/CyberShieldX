import { STATE_INFO } from "../format.js";

export function StateChip({ state, reason }) {
  let info = STATE_INFO[state] || { label: state, tone: "muted" };
  if (state === "DISABLED" && reason === "not_built") info = { label: "Not built yet", tone: "muted" };
  return <span className={`chip chip-${info.tone}`}>{info.label}</span>;
}

/** Compact row used on the dashboard. */
export function SourceStatus({ source }) {
  return (
    <li className="source-row">
      <span className="source-name">{source.name}</span>
      <StateChip state={source.state} reason={source.reason} />
    </li>
  );
}
