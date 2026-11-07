// Raw Chrome evidence only. Expected-versus-actual comparison belongs to the controller.
export function createPendingObservation({run_id, step_id, navigation_id, tab_id, url}) {
  const target = new URL(url);
  const nonce = `${run_id}-chrome-${step_id}-${navigation_id}`;
  if (target.protocol !== 'https:' || !['login.payroll.test', 'other.payroll.test'].includes(target.hostname)
      || target.port || target.pathname !== '/evidence' || target.hash
      || target.searchParams.get('request_id') !== nonce
      || [...target.searchParams].length !== 1 || !Number.isInteger(tab_id) || tab_id < 0) {
    throw new Error('Invalid tracked lab navigation');
  }
  return {run_id, step_id, navigation_id, tab_id, url: target.href,
    request_id: null, status_code: null, origin: null, terminal: false};
}

export function reduceObservation(pending, event) {
  if (!pending || pending.terminal || event.tab_id !== pending.tab_id) {
    return {pending, completed: null};
  }
  const lifecycle = event.kind === 'tab_closed' || event.kind === 'timeout';
  if (!lifecycle && (event.url !== pending.url || !event.request_id
      || (pending.request_id !== null && pending.request_id !== event.request_id))) {
    return {pending, completed: null};
  }
  if (!['headers', 'completed', 'error', 'tab_closed', 'timeout'].includes(event.kind)) {
    return {pending, completed: null};
  }
  const next = {...pending};
  if (!lifecycle) next.request_id = event.request_id;
  if (event.kind === 'headers') {
    next.status_code = event.status_code ?? null;
    next.origin = event.origin ?? null;
    return {pending: next, completed: null};
  }
  next.terminal = true;
  const outcome = lifecycle ? 'unobserved' : event.kind === 'error' ? 'error' : 'http';
  const completed = {
    run_id: next.run_id, step_id: next.step_id, navigation_id: next.navigation_id,
    source: lifecycle ? 'extension.lifecycle' : 'chrome.webRequest',
    url: next.url, outcome,
    status_code: outcome === 'http' ? (event.status_code ?? next.status_code) : null,
    origin: outcome === 'http' ? (event.origin ?? next.origin) : null,
    error: outcome === 'error' ? (event.error ?? null) : null,
    observed_at: event.observed_at ?? new Date().toISOString(),
  };
  return {pending: next, completed};
}
