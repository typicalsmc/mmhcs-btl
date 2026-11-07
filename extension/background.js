import {createPendingObservation, reduceObservation} from './observer.mjs';

const CONTROL = 'http://127.0.0.1:8765';
const DASHBOARD = chrome.runtime.getURL('dashboard.html');
const STORE = 'visualLab';
const FILTER = {urls: ['https://login.payroll.test/*', 'https://other.payroll.test/*'], types: ['main_frame']};
let queue = Promise.resolve();
let deadlineTimer;
const accessReady = chrome.storage.local.setAccessLevel({accessLevel: 'TRUSTED_CONTEXTS'});
const serial = fn => {
  const result = queue.then(() => accessReady).then(fn);
  queue = result.catch(() => {});
  return result;
};
const initial = () => ({token: '', connected: false, connection_error: null, state: null,
  attempts: [], active_navigation_id: null, checklists: {}, selected_step_id: null, acknowledged_navigation_id: null});
async function load() { return {...initial(), ...(await chrome.storage.local.get(STORE))[STORE]}; }
async function save(data) { await chrome.storage.local.set({[STORE]: data}); }
function publicData(data) {
  const {token, ...result} = data;
  return {...result, paired: Boolean(token), control_url: CONTROL};
}
function diagnostic(error) { return error instanceof Error ? error.message : String(error); }
async function request(data, path, body) {
  if (!data.token) throw new Error('Chưa ghép nối: nhập token từ console máy Docker.');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  let response;
  try {
    response = await fetch(`${CONTROL}/api/${path}`, {
      method: body === undefined ? 'GET' : 'POST', cache: 'no-store',
      headers: {Authorization: `Bearer ${data.token}`, ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
      ...(body === undefined ? {} : {body: JSON.stringify(body)}), signal: controller.signal,
    });
  } catch {
    throw new Error('Không tới được controller: kiểm tra tunnel SSH 127.0.0.1:8765 và tiến trình visual_demo.py. Nếu vừa gửi thao tác, trạng thái chưa chắc chắn; kết nối lại để đọc trạng thái, không tự gửi lại.');
  } finally { clearTimeout(timeout); }
  let payload;
  try { payload = await response.json(); } catch { throw new Error('Controller trả dữ liệu không hợp lệ; không tự gửi lại thao tác.'); }
  if (!response.ok) {
    if (response.status === 401) throw new Error('Token không đúng hoặc controller đã khởi động lại. Nhập token mới từ console.');
    if (response.status === 403) throw new Error('Controller từ chối Origin/Host. Kiểm tra --extension-id trùng ID extension này.');
    if (response.status === 409) throw new Error(`Thao tác không hợp lệ ở trạng thái hiện tại: ${payload.error || 'hãy đọc lại trạng thái'}`);
    throw new Error(`HTTP ${response.status}: ${payload.error || 'controller báo lỗi'}`);
  }
  return payload;
}
function checklistKey(data, id) {
  return `${data.state?.run_id || ''}:${id}:${data.state?.setup?.root_sha256 || ''}`;
}
function currentAttempt(data) { return data.attempts.find(a => a.pending.navigation_id === data.active_navigation_id); }
function armDeadline(data) {
  clearTimeout(deadlineTimer);
  const attempt = currentAttempt(data);
  if (attempt && !attempt.pending.terminal) {
    deadlineTimer = setTimeout(() => { serial(() => expire()).catch(() => {}); }, Math.max(1, attempt.deadline - Date.now()));
  }
}
async function syncEvidence(data) {
  if (!data.connected) return;
  for (const attempt of data.attempts) {
    if (!attempt.completed || attempt.synced) continue;
    // Old-run evidence remains locally visible, but cannot be submitted to a new controller run.
    if (attempt.completed.run_id !== data.state?.run_id) continue;
    const alreadyCaptured = data.state?.browser_observations.some(record =>
      record.navigation_id === attempt.completed.navigation_id);
    if (attempt.completed.step_id !== data.state?.current_step_id && !alreadyCaptured) {
      // Another profile may have advanced the run. Preserve this attempt, but never let
      // its inevitable current-step rejection block new evidence (especially recovery).
      attempt.sync_error = 'Bước này đã kết thúc trên controller; bằng chứng chưa gửi được giữ cục bộ, không chặn bước hiện tại.';
      await save(data);
      continue;
    }
    try {
      const stored = await request(data, 'browser-observations', attempt.completed);
      attempt.synced = true;
      attempt.server_record = stored;
      attempt.sync_error = null;
      await save(data);
    } catch (error) {
      attempt.sync_error = diagnostic(error);
      data.connection_error = diagnostic(error);
      // An observation may be resent idempotently, never a deployment mutation.
      await save(data);
      break;
    }
  }
}
async function acceptEvent(data, event) {
  const attempt = currentAttempt(data);
  if (!attempt) return;
  const result = reduceObservation(attempt.pending, event);
  if (result.pending === attempt.pending) return;
  attempt.pending = result.pending;
  if (result.completed) {
    attempt.completed = result.completed;
    attempt.synced = false;
  }
  await save(data); // Commit raw evidence before any network I/O.
  armDeadline(data);
  if (result.completed) await syncEvidence(data);
}
async function expire() {
  const data = await load();
  const attempt = currentAttempt(data);
  if (attempt && !attempt.pending.terminal && Date.now() >= attempt.deadline) {
    await acceptEvent(data, {kind: 'timeout', tab_id: attempt.pending.tab_id, observed_at: new Date().toISOString()});
  } else armDeadline(data);
}
function chromeEvent(kind, details) {
  const headers = details.responseHeaders || [];
  const marker = headers.find(header => header.name.toLowerCase() === 'x-lab-origin');
  const event = {kind, tab_id: details.tabId, url: details.url, request_id: details.requestId,
    status_code: details.statusCode ?? null, origin: marker?.value ?? null,
    error: details.error ?? null, observed_at: new Date(details.timeStamp).toISOString()};
  serial(async () => acceptEvent(await load(), event)).catch(() => {});
}
// Register synchronously, before storage initialization, so a worker wakeup cannot miss fast TLS events.
chrome.webRequest.onHeadersReceived.addListener(details => chromeEvent('headers', details), FILTER, ['responseHeaders']);
chrome.webRequest.onCompleted.addListener(details => chromeEvent('completed', details), FILTER);
chrome.webRequest.onErrorOccurred.addListener(details => chromeEvent('error', details), FILTER);
chrome.tabs.onRemoved.addListener(tab_id => {
  serial(async () => acceptEvent(await load(), {kind: 'tab_closed', tab_id, observed_at: new Date().toISOString()})).catch(() => {});
});
chrome.runtime.onStartup.addListener(() => {
  serial(async () => {
    const data = await load();
    const attempt = currentAttempt(data);
    if (attempt && !attempt.pending.terminal) {
      await acceptEvent(data, {kind: 'tab_closed', tab_id: attempt.pending.tab_id, observed_at: new Date().toISOString()});
    }
  }).catch(() => {});
});
chrome.action.onClicked.addListener(() => { chrome.tabs.create({url: DASHBOARD}); });

async function refresh(data) {
  if (!data.connected) return;
  try {
    data.state = await request(data, 'state');
    data.connection_error = null;
  } catch (error) {
    data.connection_error = diagnostic(error);
    data.connected = false;
  }
  await save(data);
}
async function openNavigation(data, step_id) {
  if (!data.connected) throw new Error('Kết nối controller trước khi mở website.');
  await refresh(data);
  const state = data.state;
  if (!data.connected || !['ready', 'complete'].includes(state?.status) || state.current_step_id !== step_id) {
    throw new Error('Chỉ mở bước hiện tại sau khi chuẩn bị tham chiếu hoàn tất.');
  }
  const step = state.steps.find(item => item.id === step_id);
  const checked = data.checklists[checklistKey(data, step_id)] || [];
  if (!step.checklist_vi.every((_, index) => checked[index] === true)) {
    throw new Error('Cần xác nhận đầy đủ checklist cấu hình Chrome trước khi mở.');
  }
  const active = currentAttempt(data);
  if (active && !active.pending.terminal) {
    await acceptEvent(data, {kind: 'tab_closed', tab_id: active.pending.tab_id, observed_at: new Date().toISOString()});
  }
  const navigation_id = crypto.randomUUID();
  const url = new URL(step.browser_url);
  url.search = '';
  url.searchParams.set('request_id', `${state.run_id}-chrome-${step_id}-${navigation_id}`);
  const tab = await chrome.tabs.create({url: 'about:blank', active: true});
  let pending;
  try {
    pending = createPendingObservation({run_id: state.run_id, step_id, navigation_id, tab_id: tab.id, url: url.href});
    data.attempts.push({pending, deadline: Date.now() + 15000, completed: null, synced: false, sync_error: null});
    data.active_navigation_id = navigation_id;
    await save(data); // Persist correlation BEFORE navigation, including fast certificate errors.
  } catch (error) {
    await chrome.tabs.remove(tab.id);
    throw error;
  }
  armDeadline(data);
  try { await chrome.tabs.update(tab.id, {url: pending.url}); }
  catch (error) {
    await acceptEvent(data, {kind: 'tab_closed', tab_id: tab.id, observed_at: new Date().toISOString()});
    throw new Error(`Không thể điều hướng tab: ${diagnostic(error)}`);
  }
}
async function handle(message) {
  await expire();
  const data = await load();
  switch (message.action) {
    case 'get':
      await refresh(data);
      break;
    case 'connect':
      if (typeof message.token === 'string' && message.token.trim()) data.token = message.token.trim();
      data.state = await request(data, 'state');
      data.connected = true;
      data.connection_error = null;
      await save(data);
      await syncEvidence(data);
      await refresh(data);
      break;
    case 'disconnect':
      data.connected = false;
      data.connection_error = null;
      await save(data);
      break;
    case 'forget':
      data.token = '';
      data.connected = false;
      data.connection_error = null;
      await save(data);
      break;
    case 'select':
      if (!data.state?.steps.some(step => step.id === message.step_id)) throw new Error('Bước không hợp lệ.');
      data.selected_step_id = message.step_id;
      await save(data);
      break;
    case 'checklist': {
      const step = data.state?.steps.find(item => item.id === message.step_id);
      if (!step || !Array.isArray(message.checked) || message.checked.length !== step.checklist_vi.length
          || message.checked.some(value => typeof value !== 'boolean')) throw new Error('Checklist không hợp lệ.');
      data.checklists[checklistKey(data, message.step_id)] = message.checked;
      await save(data);
      break;
    }
    case 'acknowledge': {
      const records = data.state?.browser_observations.filter(item => item.step_id === data.state.current_step_id) || [];
      const latest = records.at(-1);
      if (latest?.comparison !== 'mismatch') throw new Error('Không có sai khác cuối cùng để xác nhận.');
      data.acknowledged_navigation_id = latest.navigation_id;
      await save(data);
      break;
    }
    case 'start':
    case 'prepare':
    case 'stop': {
      if (!data.connected) throw new Error('Cần kết nối lại và đọc trạng thái trước thao tác.');
      await refresh(data);
      if (!data.connected) throw new Error(data.connection_error);
      let path = message.action;
      let body = {};
      if (message.action === 'prepare') {
        path = 'next';
        if (data.state.status !== 'ready' || data.state.next_step_id !== message.step_id) throw new Error('Chỉ chuẩn bị đúng bước kế tiếp một lần.');
        const latest = data.state.browser_observations.filter(item => item.step_id === data.state.current_step_id).at(-1);
        body = {step_id: message.step_id, acknowledge_mismatch: Boolean(latest && latest.navigation_id === data.acknowledged_navigation_id)};
      } else if (message.action === 'start' && data.state.status !== 'idle') throw new Error('Start chỉ dùng khi controller idle.');
      else if (message.action === 'stop' && !['ready', 'complete', 'failed'].includes(data.state.status)) throw new Error('Chờ thao tác hiện tại hoàn tất trước khi Stop.');
      try {
        await request(data, path, body); // Exactly once. No replay after timeouts, worker restart, or reconnect.
      } catch (error) {
        data.connected = false;
        data.connection_error = diagnostic(error);
        await save(data);
        throw error;
      }
      await refresh(data);
      if (message.action === 'prepare') data.selected_step_id = message.step_id;
      await save(data);
      break;
    }
    case 'open':
      await openNavigation(data, message.step_id);
      break;
    default:
      throw new Error('Thông điệp dashboard không hợp lệ.');
  }
  armDeadline(data);
  return publicData(data);
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || sender.url !== DASHBOARD || !message || typeof message.action !== 'string') {
    sendResponse({ok: false, error: 'Chỉ dashboard tin cậy được gửi lệnh.'});
    return false;
  }
  serial(() => handle(message)).then(data => sendResponse({ok: true, data}), error => sendResponse({ok: false, error: diagnostic(error)}));
  return true;
});
