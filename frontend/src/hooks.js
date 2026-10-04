import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "./api.js";

export function useApi(path) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setState((s) => ({ ...s, loading: true, error: null }));
    api
      .get(path, { signal: controller.signal })
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error) => {
        if (error.name !== "AbortError") setState({ data: null, error, loading: false });
      });
    return () => controller.abort();
  }, [path, tick]);

  return { ...state, reload };
}

export const AppDataContext = createContext({ config: null, modules: null, refreshConfig: () => {} });
export const useAppData = () => useContext(AppDataContext);
