import Report from "../components/Report.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { useApi } from "../hooks.js";

export default function ScanDetail({ scanId }) {
  const { data, error, loading, reload } = useApi(`/scans/${encodeURIComponent(scanId)}`);

  if (loading && !data) return <LoadingState label="Loading scan" />;
  if (error) return <ErrorState title="This scan could not load" message={error.message} onRetry={reload} />;
  if (!data?.report || !data.report.target) {
    return <ErrorState title="No report saved for this scan" message="It may have been created before reporting existed." />;
  }
  const report = { ...data.report, scan_id: data.id, is_demo: data.is_demo };
  return <Report report={report} />;
}
