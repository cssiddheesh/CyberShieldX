import { useState } from "react";
import { api } from "../api.js";
import Icon from "../components/Icon.jsx";
import { ErrorState, LoadingState } from "../components/States.jsx";
import { useApi } from "../hooks.js";

function QuizRunner({ moduleKey, moduleLabel, onExit }) {
  const { data, error, loading } = useApi(`/lab/quiz/${moduleKey}`);
  const [picked, setPicked] = useState({});
  const [result, setResult] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (loading && !data) return <LoadingState label="Loading questions" />;
  if (error) return <ErrorState title="Questions could not load" message={error.message} />;

  const submit = async () => {
    setSubmitting(true);
    try {
      const answers = data.questions.map((q) => picked[q.id] ?? -1);
      setResult(await api.post("/lab/submit", { module: moduleKey, answers }));
    } catch (e) {
      setResult({ error: e.message });
    } finally {
      setSubmitting(false);
    }
  };

  if (result?.results) {
    return (
      <section className="panel">
        <h2 className="panel-title">{moduleLabel}: {result.score}/{result.total} ({result.percent}%)</h2>
        <p>{result.band}</p>
        <div className="stack">
          {result.results.map((r) => {
            const q = data.questions[r.id];
            return (
              <div key={r.id} className="evidence">
                <p><strong>Q{r.id + 1}.</strong> {q.question}</p>
                <p className={r.was_correct ? "is-ok" : "is-error"}>
                  {r.was_correct ? "✓ Correct" : `✗ You chose ${r.picked >= 0 ? `"${q.options[r.picked]}"` : "nothing"} — correct: "${q.options[r.correct]}"`}
                </p>
                <p className="muted">{r.explanation}</p>
              </div>
            );
          })}
        </div>
        <div className="form-row">
          <button className="btn btn-quiet" onClick={() => { setPicked({}); setResult(null); }}>Retry</button>
          <button className="btn" onClick={onExit}>All simulations</button>
        </div>
      </section>
    );
  }

  return (
    <section className="panel">
      <h2 className="panel-title">{moduleLabel} ({data.total} questions)</h2>
      <div className="stack">
        {data.questions.map((q) => (
          <fieldset key={q.id} className="quiz-q">
            <legend><strong>Q{q.id + 1}.</strong> {q.question}</legend>
            {q.options.map((opt, i) => (
              <label key={i} className="quiz-opt">
                <input type="radio" name={`q${q.id}`} checked={picked[q.id] === i}
                  onChange={() => setPicked((p) => ({ ...p, [q.id]: i }))} />
                {opt}
              </label>
            ))}
          </fieldset>
        ))}
      </div>
      {result?.error && <p className="scan-hint is-error">{result.error}</p>}
      <div className="form-row">
        <button className="btn" onClick={onExit}>Back</button>
        <button className="btn btn-primary" onClick={submit} disabled={submitting}>Check answers</button>
      </div>
    </section>
  );
}

export default function Lab() {
  const { data, error, loading, reload } = useApi("/lab/modules");
  const [active, setActive] = useState(null);

  if (loading && !data) return <LoadingState label="Loading threat lab" />;
  if (error) return <ErrorState title="The lab could not load" message={error.message} onRetry={reload} />;

  if (active) {
    const mod = data.modules.find((m) => m.key === active);
    return <QuizRunner moduleKey={active} moduleLabel={mod.label} onExit={() => setActive(null)} />;
  }

  return (
    <div className="stack">
      <section className="panel">
        <h2 className="panel-title">Cyber Threat Lab</h2>
        <p className="muted">Safe, educational simulations. No real attacks, no real malware, no credential harvesting — just questions that teach defensive thinking.</p>
      </section>
      <div className="card-grid">
        {data.modules.map((m) => (
          <button key={m.key} className="panel lab-card" onClick={() => setActive(m.key)}>
            <Icon name="lab" size={24} />
            <strong>{m.label}</strong>
            <span className="muted">{m.blurb}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
