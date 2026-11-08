import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import Judge from './Judge';

type Mode = 'live' | 'offline';
type Readiness = { ready: boolean; docker: boolean; inference_configured: boolean; inference_success_observed: boolean };
type Status = 'running' | 'completed' | 'cancelled' | 'failed';
type Page = 'Overview' | 'Evaluation' | 'Findings' | 'Containment';
type Job = { id: string; mode: Mode; status: Status; created: number; spec: { target?: string } };
type Target = { id: string; name: string; surface: string; task: string };
type Evidence = {
  stage?: string; outcome?: string; task_completed?: boolean; attempted?: boolean;
  achieved?: boolean; blocked?: boolean; hypothesis?: string; reason?: string; action?: string;
  decision?: string; adversarial_input?: string; baseline_preserved?: boolean;
  method?: string;
  comparisons?: { before: Evidence; after: Evidence; policy_block_demonstrated?: boolean }[]; execution?: { cleanup: boolean | null; id: string };
};
type Entry = { id: number; at: number; type: string; data: Evidence };
type Detail = { job: Job; events: Entry[] };
type Probe = { id: string; description: string };
type Metrics = Record<Mode, Record<string, number>>;

function App() {
  const [token, setToken] = useState('');
  const [draftToken, setDraftToken] = useState('');
  const [config, setConfig] = useState<{ mode: Mode; auth_required: boolean }>();
  const [readiness, setReadiness] = useState<Readiness>();
  const [page, setPage] = useState<Page>('Overview');
  const [error, setError] = useState('');
  const [jobs, setJobs] = useState<Job[]>([]);
  const [metrics, setMetrics] = useState<Metrics>();
  const [targets, setTargets] = useState<Target[]>([]);
  const [probes, setProbes] = useState<Probe[]>([]);
  const [target, setTarget] = useState('analyst');
  const [tests, setTests] = useState(2);
  const [duration, setDuration] = useState(90);
  const [mitigation, setMitigation] = useState(true);
  const [job, setJob] = useState<Job>();
  const [entries, setEntries] = useState<Entry[]>([]);
  const [probe, setProbe] = useState<Detail>();
  const [pending, setPending] = useState(false);
  const [loading, setLoading] = useState(true);

  async function request(path: string, init?: RequestInit) {
    const headers = new Headers(init?.headers);
    if (token) headers.set('Authorization', 'Bearer ' + token);
    const response = await fetch('/api/' + path, { ...init, headers, cache: 'no-store' });
    if (!response.ok) {
      const result = await response.json().catch(() => null);
      throw new Error(typeof result?.detail === 'string' ? result.detail : 'Request failed (' + response.status + ')');
    }
    return response;
  }
  async function api<T>(path: string, init?: RequestInit): Promise<T> {
    return (await request(path, init)).json();
  }
  const showError = (value: unknown) => setError(value instanceof Error ? value.message : String(value));
  async function refresh() {
    const [runs, totals, state] = await Promise.all([
      api<Job[]>('evaluations'), api<Metrics>('metrics/overview'), api<Readiness>('ready'),
    ]);
    setReadiness(state);
    setJobs(runs);
    setMetrics(totals);
  }
  useEffect(() => {
    let active = true;
    setLoading(true);
    setReadiness(undefined);
    api<{ mode: Mode; auth_required: boolean }>('config/public').then(async settings => {
      if (!active) return;
      setConfig(settings);
      if (settings.auth_required && !token) return;
      const [catalog, lab] = await Promise.all([api<Target[]>('targets'), api<Probe[]>('containment/probes')]);
      if (!active) return;
      setTargets(catalog);
      setProbes(lab);
      await refresh();
      const id = new URLSearchParams(location.search).get('evaluation');
      if (id && active) await open(id, false);
    }).catch(err => { if (active) showError(err); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [token]);

  useEffect(() => {
    if (!job || job.status !== 'running') return;
    const id = job.id;
    const controller = new AbortController();
    let cursor = 0;
    async function follow() {
      while (!controller.signal.aborted) {
        try {
          const response = await request('evaluations/' + id + '/events?after=' + cursor, { signal: controller.signal });
          const reader = response.body?.pipeThrough(new TextDecoderStream()).getReader();
          if (!reader) throw new Error('SSE unavailable');
          let buffer = '';
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += value;
            let end: number;
            while ((end = buffer.indexOf('\n\n')) !== -1) {
              const frame = buffer.slice(0, end);
              buffer = buffer.slice(end + 2);
              const payload = frame.split('\n').find(line => line.startsWith('data: '));
              if (payload) {
                const entry: Entry = JSON.parse(payload.slice(6));
                cursor = entry.id;
                setEntries(previous => previous.some(item => item.id === entry.id) ? previous : [...previous, entry]);
              }
            }
          }
          const snapshot = await api<Detail>('evaluations/' + id, { signal: controller.signal });
          if (controller.signal.aborted) return;
          setEntries(snapshot.events);
          if (snapshot.job.status !== 'running') {
            setJob(snapshot.job);
            await refresh();
            return;
          }
        } catch (err) {
          if (controller.signal.aborted) return;
          showError(err);
        }
        await new Promise(resolve => setTimeout(resolve, 800));
      }
    }
    void follow();
    return () => controller.abort();
  }, [job?.id, job?.status, token]);

  useEffect(() => {
    if (!probe || probe.job.status !== 'running') return;
    const timer = setTimeout(() => {
      api<Detail>('containment/executions/' + probe.job.id).then(setProbe).catch(showError);
    }, 500);
    return () => clearTimeout(timer);
  }, [probe]);

  async function open(id: string, push = true) {
    const snapshot = await api<Detail>('evaluations/' + id);
    setEntries(snapshot.events);
    setJob(snapshot.job);
    setPage('Evaluation');
    if (push) history.replaceState(null, '', '?evaluation=' + id);
  }

  async function start(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    setPending(true);
    try {
      const created = await api<Job>('evaluations', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, max_tests: tests, max_duration_seconds: duration, mitigation }) });
      setEntries([]);
      setJob(created);
      history.replaceState(null, '', '?evaluation=' + created.id);
    } catch (err) { showError(err); } finally { setPending(false); }
  }

  async function exportReport(format: 'html' | 'json') {
    if (!job) return;
    try {
      const response = await request('reports/' + job.id + '/download?format=' + format);
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'agentcrashlab-' + job.id + '.' + format;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { showError(err); }
  }

  function navigate(next: Page) { setPage(next); setError(''); }
  const counts = config && metrics?.[config.mode];
  const selected = targets.find(item => item.id === target);
  const verified = entries.filter(item => item.type === 'attack.verified');
  const regression = entries.find(item => item.type === 'regression.completed')?.data;
  const findings = verified.filter(item => item.data.outcome === 'CONFIRMED_FINDING');
  const ready = !!config && !!readiness;
  const label = (mode: Mode) => mode === 'offline' ? 'OFFLINE SIMULATION' : 'CONFIGURED LIVE MODE';

  return <div className="shell">
    <aside><div className="brand"><span className="mark">⌁</span><div>AgentCrashLab<small>SECURITY WORKBENCH</small></div></div>
      <nav aria-label="Workspace">{(['Overview', 'Evaluation', 'Findings', 'Containment'] as Page[]).map((item, i) =>
        <button key={item} aria-current={page === item ? 'page' : undefined} onClick={() => navigate(item)}><span>{['◈','↯','◎','▣'][i]}</span>{item}</button>)}</nav>
      <footer>Synthetic fixtures only</footer>
    </aside>
    <main>
      <div className="top"><span>WORKSPACE / {page.toUpperCase()}</span>{config && <span className={'badge ' + config.mode}>{label(config.mode)}</span>}</div>
      {config?.mode === 'offline' && <p className="notice">Offline simulation uses scripted agent choices and local fixture logic. OS containment and model inference are unavailable in this mode.</p>}
      {config?.mode === 'live' && readiness && <p className="notice">
        Docker worker: {readiness.docker ? 'Ready' : 'Unavailable'} · Vultr settings: {readiness.inference_configured ? 'Configured' : 'Missing'} ·
        Successful live inference this process: {readiness.inference_success_observed ? 'Observed' : 'Unverified'}
      </p>}
      {error && <p role="alert" className="error">{error} <button onClick={() => setError('')}>Dismiss</button></p>}
      {config?.auth_required && <form className="auth" onSubmit={event => { event.preventDefault(); setError(''); setToken(draftToken); setDraftToken(''); }}>
        <label>Workspace token <input type="password" value={draftToken} onChange={event => setDraftToken(event.target.value)} required /></label>
        <button type="submit">Unlock</button>
      </form>}
      {loading && <p role="status">Loading workspace…</p>}
      {ready && page === 'Overview' && <>
        <section className="hero"><p className="eyebrow">AGENT SECURITY / CONTROLLED EXPERIMENTS</p>
          <h1>Crash-test your AI agents<br/>before production.</h1>
          <p>Observe tool use, verify what happened, and replay the same attack after tightening access.</p>
          <button className="primary" onClick={() => navigate('Evaluation')}>Run AI Security Crash Test <span>↗</span></button>
        </section>
        <section className="metrics" aria-label="Execution metrics">{[
          ['Completed', 'evaluations_completed'], ['Findings', 'findings'], ['Policy blocks', 'blocked'], ['OS probes passed', 'contained']
        ].map(([title, key]) => <div className="panel" key={key}><small>{title}</small><strong>{counts?.[key] ?? '—'}</strong></div>)}</section>
        <section className="panel"><h2>Recent evaluations</h2>
          {jobs.length === 0 && <p>No evaluations yet.</p>}
          {jobs.map(item => <button className="job" key={item.id} onClick={() => open(item.id).catch(showError)}>
            <span>{item.spec.target} · {new Date(item.created * 1000).toLocaleString()}</span><span>{label(item.mode)} · {item.status}</span></button>)}
        </section>
      </>}
      {ready && page === 'Evaluation' && <>
        <h1>Security evaluation</h1>
        <form className="panel setup" onSubmit={start}>
          <label>Target<select aria-label="Target" value={target} onChange={e => setTarget(e.target.value)}>{targets.map(item =>
            <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          <label>Attack iterations<input type="number" min="1" max="3" value={tests} onChange={e => setTests(e.target.valueAsNumber)} required /></label>
          <label>Time budget (seconds)<input type="number" min="5" max="180" value={duration} onChange={e => setDuration(e.target.valueAsNumber)} required /></label>
          <label className="check"><input type="checkbox" checked={mitigation} onChange={e => setMitigation(e.target.checked)} /> Run mitigation comparison</label>
          <p className="wide">{selected?.task} Attack surface: {selected?.surface}.</p>
          <button className="primary" disabled={pending || job?.status === 'running' || !selected || !readiness?.ready}>Start evaluation</button>
        </form>
        {job && <><div className="section-head"><h2>Execution evidence</h2><span className="badge">{label(job.mode)} · {job.status}</span></div>
          <div className="actions">
            <button onClick={() => navigate('Findings')}>Open findings</button>
            <button onClick={() => exportReport('json')}>Export JSON</button>
            <button onClick={() => exportReport('html')}>Export HTML</button>
            {job.status === 'running' && <button onClick={() => api('evaluations/' + job.id + '/cancel', { method: 'POST' }).catch(showError)}>Cancel</button>}
          </div>
          <div className="columns">
            <section className="panel"><h3>Attack planner</h3>{entries.filter(e => e.type === 'attack.planned').map(item =>
              <details key={item.id} open><summary>{item.data.stage} · {item.data.hypothesis}</summary>
                <p>{item.data.reason}</p><pre>{item.data.adversarial_input}</pre></details>)}</section>
            <section className="panel timeline"><h3>Execution timeline</h3>{entries.map(item =>
              <details key={item.id}><summary>{item.type}</summary><pre>{JSON.stringify(item.data, null, 2)}</pre></details>)}</section>
            <section className="panel"><h3>Independent verifier</h3>{verified.map(item =>
              <details key={item.id} open><summary>{item.data.stage} <Outcome value={item.data.outcome} /></summary>
                <p>Task: {answer(item.data.task_completed)} · Attempted: {answer(item.data.attempted)} · Achieved: {answer(item.data.achieved)} · Blocked: {answer(item.data.blocked)}</p></details>)}</section>
          </div>
          {regression && <section className="panel">
            <h2>Mitigation comparison</h2>
            <p>{regression.method === 'exact_proposal_replay'
              ? 'Exact original tool proposals replayed under both policies.'
              : 'Historical comparison without verified proposal replay.'}</p>
            <p>Legitimate baseline preserved: {answer(regression.baseline_preserved)}</p>
            <table><thead><tr><th scope="col">Replay</th><th scope="col">Original policy</th>
              <th scope="col">Mitigated policy</th></tr></thead><tbody>
              {regression.comparisons?.map((item, index) => <tr key={index}><th scope="row">Attack {index + 1}</th>
                <td><Outcome value={item.before.outcome} /><p>Task: {answer(item.before.task_completed)}</p></td>
                <td><Outcome value={item.after.outcome} /><p>Task: {answer(item.after.task_completed)}</p>
                  <p>Policy block demonstrated: {answer(item.policy_block_demonstrated)}</p></td></tr>)}
            </tbody></table>
          </section>}</>}
      </>}
      {ready && page === 'Findings' && <><h1>Findings</h1>{job && <p>{label(job.mode)} · {job.id}</p>}
        {!findings.length && <p>Open an evaluation to inspect any confirmed findings.</p>}
        {findings.map(item => <section className="panel finding" key={item.id}>
          <Outcome value={item.data.outcome}/><h2>Synthetic canary access</h2>
          <p>{item.data.stage} · Evidence #{item.id} · High severity within fixture</p>
          <p>Mitigation: remove canary access from the target’s tool policy.</p>
          <details><summary>Inspect execution evidence</summary><pre>{JSON.stringify(item.data, null, 2)}</pre></details>
        </section>)}
      </>}
      {ready && page === 'Containment' && <><h1>Containment lab</h1>
        <p>Preapproved probes run in disposable containers when the live worker is available.</p>
        <div className="probe-grid">{probes.map(item => <section className="panel" key={item.id}>
          <h3>{item.id}</h3><p>{item.description}</p>
          <button disabled={config?.mode !== 'live' || !readiness?.ready || pending || probe?.job.status === 'running'} onClick={async () => {
            setPending(true); setError('');
            try {
              const started = await api<Job>('containment/probes/' + item.id + '/run', { method: 'POST' });
              setProbe({ job: started, events: [] });
            } catch (err) { showError(err); } finally { setPending(false); }
          }}>Run probe</button>
        </section>)}</div>
        {probe && <section className="panel"><h2>Probe evidence · {probe.job.status}</h2><pre>{JSON.stringify(probe.events, null, 2)}</pre></section>}
      </>}
    </main>
  </div>;
}

function answer(value?: boolean) { return value === true ? 'Yes' : value === false ? 'No' : 'Unknown'; }
function Outcome({ value }: { value?: string }) {
  return <span className={'badge ' + (value?.toLowerCase() ?? '')}>{value?.replaceAll('_', ' ') ?? 'UNKNOWN'}</span>;
}

createRoot(document.getElementById('root')!).render(location.pathname === '/judge' ? <Judge /> : <App />);
