import Icon from "../components/Icon.jsx";
import { Link } from "../router.jsx";

export function Planned({ module }) {
  return (
    <div className="stack narrow">
      <section className="panel planned">
        <Icon name={module.key} size={32} />
        <h2>{module.label} isn't available yet</h2>
        <p>{module.blurb}</p>
        <p className="muted">This module is planned for build phase {module.phase}. Nothing on this page analyzes anything yet.</p>
        <Link to="/" className="btn">Back to the dashboard</Link>
      </section>
    </div>
  );
}

export function NotFound() {
  return (
    <div className="stack narrow">
      <section className="panel planned">
        <Icon name="alert" size={32} />
        <h2>Page not found</h2>
        <p className="muted">There is no page at this address.</p>
        <Link to="/" className="btn">Back to the dashboard</Link>
      </section>
    </div>
  );
}
