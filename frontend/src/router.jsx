import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

const RouterContext = createContext(null);

const normalize = (path) => path.replace(/\/+$/, "") || "/";
const read = () => ({ path: normalize(window.location.pathname), search: window.location.search });

export function Router({ children }) {
  const [location, setLocation] = useState(read);

  useEffect(() => {
    const onPop = () => setLocation(read());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navigate = useCallback((to, { replace = false } = {}) => {
    const url = new URL(to, window.location.origin);
    window.history[replace ? "replaceState" : "pushState"](null, "", url.pathname + url.search);
    setLocation(read());
    window.scrollTo(0, 0);
  }, []);

  const value = useMemo(() => ({ ...location, navigate }), [location, navigate]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export const useRouter = () => useContext(RouterContext);

export function Link({ to, children, onClick, ...rest }) {
  const { navigate } = useRouter();
  const handle = (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    onClick?.(event);
    navigate(to);
  };
  return (
    <a href={to} onClick={handle} {...rest}>
      {children}
    </a>
  );
}
