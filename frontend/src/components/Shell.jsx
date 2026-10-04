import { useEffect, useState } from "react";
import { Link, useRouter } from "../router.jsx";
import Icon from "./Icon.jsx";

const GROUP_ORDER = ["Overview", "Analyzers", "Learn", "Records", "System"];

export function Brand() {
  return (
    <Link to="/" className="brand" aria-label="CyberShield X home">
      <span className="brand-mark"><Icon name="shield" size={20} /></span>
      <span className="brand-text">
        <strong>CyberShield X</strong>
        <span>360° security intelligence</span>
      </span>
    </Link>
  );
}

export function Sidebar({ modules, open, onClose }) {
  const { path } = useRouter();
  const groups = GROUP_ORDER.map((name) => ({ name, items: modules.filter((m) => m.group === name) })).filter((g) => g.items.length);
  const isActive = (m) => (m.path === "/" ? path === "/" : path === m.path || path.startsWith(m.path + "/"));
  return (
    <>
      <div className={`scrim${open ? " is-open" : ""}`} onClick={onClose} />
      <aside className={`sidebar${open ? " is-open" : ""}`} aria-label="Main navigation">
        <Brand />
        <nav>
          {groups.map((g) => (
            <div className="nav-group" key={g.name}>
              <p className="nav-heading">{g.name}</p>
              {g.items.map((m) => (
                <Link key={m.key} to={m.path} onClick={onClose}
                  className={`nav-item${isActive(m) ? " is-active" : ""}`} aria-current={isActive(m) ? "page" : undefined}>
                  <Icon name={m.key} />
                  <span>{m.label}</span>
                  {m.status !== "available" && <span className="nav-soon">Soon</span>}
                </Link>
              ))}
            </div>
          ))}
        </nav>
      </aside>
    </>
  );
}

export function TopBar({ title, demoMode, onMenu }) {
  return (
    <header className="topbar">
      <button className="icon-btn menu-btn" onClick={onMenu} aria-label="Open navigation"><Icon name="menu" /></button>
      <h1 className="topbar-title">{title}</h1>
      <div className="topbar-right">
        {demoMode && (
          <span className="demo-badge" title="Results shown while Demo Mode is on are DEMONSTRATION DATA, not live intelligence.">
            DEMO MODE
          </span>
        )}
      </div>
    </header>
  );
}

export function AppShell({ modules, title, demoMode, children }) {
  const [open, setOpen] = useState(false);
  const { path } = useRouter();
  useEffect(() => { document.title = title ? `${title} - CyberShield X` : "CyberShield X"; }, [title]);
  useEffect(() => setOpen(false), [path]);
  return (
    <div className="shell">
      <Sidebar modules={modules} open={open} onClose={() => setOpen(false)} />
      <div className="main">
        {demoMode && (
          <div className="demo-banner" role="status">
            Demo Mode is on. Any results shown are DEMONSTRATION DATA, not live threat intelligence.
          </div>
        )}
        <TopBar title={title} demoMode={demoMode} onMenu={() => setOpen(true)} />
        <main className="content" id="content">{children}</main>
        <footer className="footer">
          CyberShield X is an educational analysis tool, not an antivirus or a replacement for professional security
          products. Risk scores are internal assessments. A source finding nothing does not prove something is safe.
        </footer>
      </div>
    </div>
  );
}
