import Icon from "./Icon.jsx";

export function LoadingState({ label = "Loading" }) {
  return (
    <div className="state" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <p className="state-title">{label}</p>
    </div>
  );
}

export function ErrorState({ title = "Something went wrong", message, onRetry }) {
  return (
    <div className="state state-error" role="alert">
      <Icon name="alert" size={28} />
      <p className="state-title">{title}</p>
      {message && <p className="state-text">{message}</p>}
      {onRetry && (
        <button className="btn" onClick={onRetry}>
          <Icon name="refresh" size={16} /> Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ icon = "inbox", title, children, action }) {
  return (
    <div className="state">
      <Icon name={icon} size={28} />
      <p className="state-title">{title}</p>
      {children && <p className="state-text">{children}</p>}
      {action}
    </div>
  );
}
