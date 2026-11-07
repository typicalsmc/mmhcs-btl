import {windowsGuide} from './windows.mjs';

const $ = id => document.getElementById(id);
let view;
let operation = false;
let timer;
let closed = false;
const labels = {idle: 'Chưa Start', busy: 'Đang thực hiện', ready: 'Sẵn sàng', complete: 'Đã có quan sát cuối', failed: 'Có lỗi vận hành', stopped: 'Đã dừng'};
const labActions = {
  baseline: 'Giữ DNS ở máy chủ thật. Probe tham chiếu kiểm tra chuỗi và CRL, truy vấn OCSP CA trung gian.',
  untrusted: 'Đổi DNS sang attacker. Probe tham chiếu chỉ tin một root không liên quan; Chrome cần gỡ đúng Root lab theo hướng dẫn.',
  forged: 'Giữ nguyên attacker và chứng chỉ. Probe tham chiếu tin Root; không đổi certificate để tạo kết quả.',
  hostname: 'Giữ nguyên hạ tầng và certificate login.payroll.test; điều hướng thật sang other.payroll.test.',
  revoked: 'Thu hồi CA trung gian vì CACompromise, xuất bản CRL và truy vấn OCSP. Đây là thao tác một lần, không tự chạy lại.',
  unchecked: 'Giữ nguyên attacker, chứng chỉ và thông tin thu hồi. Chỉ probe tham chiếu bỏ kiểm tra CRL; Chrome cần hai policy hiệu lực bằng 0.',
  recovery: 'Tạo CA trung gian thay thế, cấp lại leaf cho server thật và đưa DNS về server thật. Giữ Root gốc và trạng thái thu hồi CA cũ.',
};
const points = {
  baseline: 'Mốc hợp lệ: đúng hostname, chuỗi tới Root đã tin, CA chưa bị thu hồi. OCSP GOOD hiển thị ở thẻ tham chiếu, không phải kết luận Chrome.',
  untrusted: 'Refresh không thay đổi trust. Chỉ xóa đúng thumbprint lab trong mọi kho áp dụng; không xóa các CA khác.',
  forged: 'Chrome chấp nhận một certificate không chứng minh website an toàn khi khóa CA đã lộ. Mở trình xem chứng chỉ Chrome để trình bày chuỗi.',
  hostname: 'Đúng chuỗi không bù được sai hostname. Không cấp lại hoặc đổi tên certificate để “sửa” bước này.',
  revoked: 'Thứ bị thu hồi là CA trung gian, không phải leaf attacker. OCSP REVOKED/ca_compromise bên tham chiếu không thay thế lỗi Chrome thực tế.',
  unchecked: 'Công bố thu hồi chỉ bảo vệ client thực sự thực thi. Nếu Chrome strict vẫn chặn, giữ nguyên sai khác; không vượt interstitial hay tắt xác minh chung.',
  recovery: 'Khôi phục không phải tin lại CA bị lộ hoặc bỏ kiểm tra thu hồi: issuer/leaf mới, Root không đổi, CA cũ vẫn revoked.',
};
function node(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = String(text);
  if (className) result.className = className;
  return result;
}
function notice(text, error = false) {
  $('notice').textContent = text;
  $('notice').hidden = !text;
  $('notice').classList.toggle('error', error);
}
async function send(action, extra = {}) {
  const response = await chrome.runtime.sendMessage({action, ...extra});
  if (!response?.ok) throw new Error(response?.error || 'Service worker không phản hồi. Mở lại dashboard để đọc trạng thái; không tự lặp thao tác.');
  return response.data;
}
function schedule() {
  clearTimeout(timer);
  if (closed) return;
  timer = setTimeout(poll, view?.connected && view?.state?.status === 'busy' ? 1000 : 3000);
}
async function poll() {
  if (operation || closed) return schedule();
  try { view = await send('get'); render(); }
  catch (error) { notice(error.message, true); }
  schedule();
}
async function act(action, extra = {}) {
  if (operation) return;
  operation = true;
  notice('');
  render();
  try {
    view = await send(action, extra);
    if (action === 'connect') {
      $('pairing-token').value = '';
      notice('Đã kết nối và đọc trạng thái. Bằng chứng chờ đồng bộ được gửi idempotent; không thao tác triển khai nào được phát lại.');
    } else if (action === 'forget') {
      $('pairing-token').value = '';
      notice('Đã quên token. Deployment không bị dừng; muốn dừng cần ghép nối lại và Stop.');
    } else if (action === 'disconnect') notice('Đã ngắt kết nối điều khiển. Docker và tab website vẫn giữ nguyên.');
  } catch (error) {
    notice(error.message, true);
    // Reading state after uncertainty is safe; never resubmit a mutating action.
    try { view = await send('get'); } catch { /* Retain the last public snapshot. */ }
  } finally {
    operation = false;
    render();
    schedule();
  }
}
function selectedStep(state) {
  return state?.steps.find(step => step.id === view.selected_step_id)
    || state?.steps.find(step => step.id === (state.current_step_id || state.next_step_id))
    || state?.steps[0];
}
function checksFor(step) {
  const key = `${view.state?.run_id || ''}:${step.id}:${view.state?.setup?.root_sha256 || ''}`;
  return view.checklists[key] || step.checklist_vi.map(() => false);
}
function pill(element, text, kind = 'subtle') {
  element.textContent = text;
  element.className = `pill ${kind}`;
}
function expectedText(expected) {
  if (expected.kind === 'http') return `HTTP ${expected.status_code} · ${expected.origin === 'legitimate' ? 'LEGITIMATE' : 'ATTACKER'} PAYROLL LAB`;
  return expected.error;
}
function comparisonText(record) {
  return record?.comparison === 'match' ? 'Khớp mong đợi' : record?.comparison === 'mismatch' ? 'Sai khác thực tế'
    : record?.comparison === 'unobserved' ? 'Chưa quan sát được' : 'Chưa có so sánh server';
}
function rows(container, values) {
  const list = node('dl', undefined, 'evidence-list');
  for (const [key, value] of values) {
    list.append(node('dt', key), node('dd', value === null || value === undefined ? 'Không quan sát được / null' : typeof value === 'object' ? JSON.stringify(value) : value));
  }
  container.append(list);
}
function rawDetails(container, title, data) {
  const details = node('details');
  details.append(node('summary', title), node('pre', JSON.stringify(data, null, 2)));
  container.append(details);
}
function renderChecklist(step) {
  const target = $('checklist');
  if (!step) { target.replaceChildren(node('p', 'Checklist sẽ có sau khi kết nối controller.', 'empty')); return; }
  const checked = checksFor(step);
  const signature = JSON.stringify([view.state.run_id, step.id, view.state.setup?.root_sha256, step.checklist_vi, checked]);
  if (target.dataset.signature === signature) return;
  target.dataset.signature = signature;
  target.replaceChildren();
  step.checklist_vi.forEach((text, index) => {
    const label = node('label', undefined, 'check-item');
    const input = node('input');
    input.type = 'checkbox';
    input.id = `check-${step.id}-${index}`;
    input.checked = checked[index] === true;
    input.addEventListener('change', () => {
      const values = [...target.querySelectorAll('input')].map(item => item.checked);
      act('checklist', {step_id: step.id, checked: values});
    });
    label.append(input, node('span', text));
    target.append(label);
  });
}
function renderCommands(state, step) {
  const target = $('windows-commands');
  const setup = state?.setup;
  const signature = JSON.stringify([setup, state?.run_id, step?.id]);
  if (target.dataset.signature === signature) return;
  target.dataset.signature = signature;
  target.replaceChildren();
  $('fingerprints').replaceChildren();
  if (setup) {
    rows($('fingerprints'), [['Root DER SHA-256 · dấu vân tay bảo mật', setup.root_sha256], ['Root SHA-1 · chỉ định danh kho Windows', setup.root_sha1], ['Gateway IP thực', setup.lab_ip]]);
  }
  $('commands-hint').textContent = setup ? `— ${step?.id || 'thiết lập'}` : '— điền giá trị thật sau Start';
  for (const item of windowsGuide(setup, state?.run_id, step?.id)) {
    const card = node('section', undefined, 'command-card');
    card.append(node('h3', item.title), node('p', item.text));
    if (item.command) {
      const copy = node('button', 'Sao chép', 'copy secondary');
      copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(item.command); copy.textContent = 'Đã sao chép'; }
        catch { notice('Không thể sao chép tự động. Chọn và sao chép lệnh trong khung.', true); }
      });
      card.append(copy, node('pre', item.command));
    }
    target.append(card);
  }
}
function renderRail(state, step) {
  const target = $('step-rail');
  target.replaceChildren();
  if (!state?.steps?.length) {
    for (let index = 0; index < 7; index++) {
      const placeholder = node('div', undefined, 'step-item placeholder');
      placeholder.append(node('span', String(index + 1).padStart(2, '0'), 'step-number'), node('span', 'Chờ catalog từ controller'));
      target.append(placeholder);
    }
    return;
  }
  state.steps.forEach((item, index) => {
    const button = node('button', undefined, `step-item${item.id === step?.id ? ' selected' : ''}`);
    button.dataset.stepId = item.id;
    button.setAttribute('aria-current', item.id === step?.id ? 'step' : 'false');
    const meta = node('span', undefined, 'step-label');
    const record = state.browser_observations.filter(record => record.step_id === item.id).at(-1);
    const label = record ? comparisonText(record) : state.current_step_id === item.id ? 'Bước hiện tại' : state.next_step_id === item.id ? 'Kế tiếp · chưa chuẩn bị' : state.reference_results.some(row => row.id === item.id) ? 'Đã có tham chiếu' : 'Xem trước';
    meta.append(node('strong', item.title), node('small', label));
    button.append(node('span', String(index + 1).padStart(2, '0'), 'step-number'), meta);
    button.addEventListener('click', () => act('select', {step_id: item.id}));
    target.append(button);
  });
}
function renderEvidence(state, step) {
  const browser = $('chrome-evidence');
  const reference = $('reference-evidence');
  browser.replaceChildren();
  reference.replaceChildren();
  const records = state?.browser_observations.filter(record => record.step_id === step?.id) || [];
  const attempts = view?.attempts.filter(attempt => attempt.pending.run_id === state?.run_id && attempt.pending.step_id === step?.id) || [];
  const local = attempts.at(-1);
  const latest = records.at(-1);
  const awaiting = local && (!local.completed || !local.synced);
  const shown = awaiting ? local.completed : latest;
  const kind = awaiting ? 'subtle' : latest?.comparison === 'match' ? 'success' : latest?.comparison === 'mismatch' ? 'warning' : 'subtle';
  pill($('chrome-verdict'), awaiting ? local.completed ? 'Chưa đồng bộ' : 'Đang chờ event' : latest ? comparisonText(latest) : 'Chưa quan sát', kind);
  if (shown) {
    rows(browser, [['Nguồn', shown.source], ['Kết quả thô', shown.outcome], ['HTTP status', shown.status_code], ['X-Lab-Origin thực', shown.origin], ['Lỗi Chrome nguyên văn', shown.error], ['Quan sát lúc', shown.observed_at], ['So sánh từ controller', awaiting ? 'Chưa đồng bộ · không kết luận' : comparisonText(latest)]]);
    rawDetails(browser, 'URL & navigation ID thực', {url: shown.url, navigation_id: shown.navigation_id});
  } else browser.append(node('p', local ? 'Tab đã được theo dõi. Sau 15 giây không có terminal event, kết quả là unobserved; không suy ra lỗi chứng chỉ.' : 'Chưa có điều hướng Chrome cho bước này. Hoàn tất checklist rồi “Mở trong Chrome”.', 'empty'));
  if (local?.sync_error && !local.synced) browser.append(node('p', `Chưa đồng bộ: ${local.sync_error}. Kết nối lại để gửi bằng chứng đã lưu.`, 'inline-error'));
  if (records.length || attempts.length) {
    const history = node('details', undefined, 'attempt-history');
    history.append(node('summary', `Mọi lần quan sát (${new Set([...records.map(record => record.navigation_id), ...attempts.map(attempt => attempt.pending.navigation_id)]).size})`));
    const ordered = [...records.map(record => ({record, synced: true}))];
    for (const attempt of attempts) {
      if (!records.some(record => record.navigation_id === attempt.pending.navigation_id)) ordered.push({record: attempt.completed || {navigation_id: attempt.pending.navigation_id, outcome: 'đang chờ'}, synced: attempt.synced});
    }
    for (const entry of ordered) {
      const item = node('div', undefined, 'attempt');
      item.append(node('strong', `${entry.record.outcome} · ${entry.synced ? comparisonText(entry.record) : 'Chưa đồng bộ'}`), node('code', entry.record.navigation_id));
      rawDetails(item, 'Bằng chứng gốc', entry.record);
      history.append(item);
    }
    browser.append(history);
  }
  const row = state?.reference_results.find(row => row.id === step?.id);
  pill($('reference-verdict'), row ? row.passed ? 'Tham chiếu đạt' : 'Tham chiếu không đạt' : 'Chưa chuẩn bị', row ? row.passed ? 'success' : 'warning' : 'subtle');
  if (row) {
    rows(reference, [['Client tham chiếu chấp nhận', row.accepted], ['HTTP tham chiếu', row.http_status], ['Origin tham chiếu', row.http_origin], ['Mã xác minh OpenSSL', row.verify_code], ['Trust của probe', row.trust], ['Kiểm tra CRL của probe', row.crl_enabled]]);
    if (row.ocsp !== undefined) rawDetails(reference, 'OCSP tham chiếu OpenSSL', row.ocsp);
    rawDetails(reference, 'Chi tiết tham chiếu: certificate / issuer / fingerprint', row);
  } else reference.append(node('p', 'Chuẩn bị đúng bước kế tiếp để chạy probe tham chiếu một lần. Không có kết quả giả định.', 'empty'));
}
function render() {
  if (!view) return;
  const state = view.state;
  const step = selectedStep(state);
  const connected = view.connected;
  const status = state?.status;
  const busy = operation || status === 'busy';
  const remote = state?.browser_observations.filter(record => record.step_id === state.current_step_id).at(-1);
  const local = view.attempts.filter(attempt => attempt.pending.run_id === state?.run_id && attempt.pending.step_id === state?.current_step_id).at(-1);
  const pending = local && (!local.completed || !local.synced);
  const terminal = remote && remote.source === 'chrome.webRequest' && ['http', 'error'].includes(remote.outcome);
  const acknowledged = remote?.acknowledged_mismatch || remote?.navigation_id === view.acknowledged_navigation_id;
  const canAdvance = !state?.current_step_id || (!pending && terminal && (remote.comparison !== 'mismatch' || acknowledged));
  pill($('connection-status'), connected ? '● Đã kết nối' : view.paired ? '○ Đã ghép · ngoại tuyến' : '○ Chưa ghép nối', connected ? 'success' : 'subtle');
  pill($('run-status'), labels[status] || 'Chưa có phiên', status === 'busy' ? 'busy' : status === 'failed' ? 'warning' : 'subtle');
  $('extension-id').textContent = chrome.runtime.id;
  $('progress-label').textContent = `${state?.reference_results.length || 0} / 7`;
  $('session-info').textContent = state?.run_id ? `RUN ${state.run_id}${!connected ? ' · bản lưu, chưa xác nhận trạng thái mới' : ''}` : 'Chưa tạo deployment';
  if (view.connection_error) notice(view.connection_error, true);
  else if (state?.error) notice(`Controller: ${state.error}`, true);
  renderRail(state, step);
  if (step) {
    $('step-counter').textContent = `BƯỚC ${String(state.steps.indexOf(step) + 1).padStart(2, '0')} / 07 · ${step.id.toUpperCase()}`;
    $('step-title').textContent = step.title;
    $('step-meaning').textContent = step.meaning_vi;
    $('lab-action').textContent = labActions[step.id] || 'Chuẩn bị theo catalog controller.';
    $('expected-result').textContent = expectedText(step.browser_expected);
    $('talking-point').textContent = points[step.id] || step.meaning_vi;
    pill($('step-phase'), state.current_step_id === step.id ? 'Bước đang đo' : state.next_step_id === step.id ? 'Bước kế tiếp' : 'Xem thẻ', 'subtle');
  }
  renderChecklist(step);
  renderCommands(state, step);
  renderEvidence(state, step);
  const checklistDone = step && step.checklist_vi.every((_, index) => checksFor(step)[index] === true);
  const canOpen = connected && !busy && ['ready', 'complete'].includes(status) && state.current_step_id === step?.id && checklistDone;
  const attemptsForStep = view.attempts.some(attempt => attempt.pending.run_id === state?.run_id && attempt.pending.step_id === step?.id)
    || state?.browser_observations.some(record => record.step_id === step?.id);
  $('start').disabled = !connected || busy || status !== 'idle';
  $('prepare').disabled = !connected || busy || status !== 'ready' || state.next_step_id !== step?.id || !canAdvance;
  $('prepare').textContent = step ? `Chuẩn bị ${state.steps.indexOf(step) + 1}` : 'Chuẩn bị bước';
  $('open-chrome').disabled = !canOpen;
  $('reobserve').disabled = !canOpen || !attemptsForStep;
  $('next').disabled = !connected || busy || status !== 'ready' || !state.next_step_id || !state.current_step_id || !canAdvance;
  $('stop').disabled = !connected || busy || !['ready', 'complete', 'failed'].includes(status);
  $('stop').title = status === 'busy' ? 'Đợi thao tác đang chạy hoàn tất. Stop không hủy giữa revoke/recovery.' : 'Chụp logs và dừng đúng deployment của phiên này';
  $('reset-checklist').disabled = !step || operation;
  $('connect').disabled = operation;
  $('disconnect').disabled = operation || !connected;
  $('forget').disabled = operation || !view.paired;
  const mismatch = remote?.comparison === 'mismatch' && step?.id === state.current_step_id;
  $('mismatch-panel').hidden = !mismatch;
  $('acknowledge').disabled = !connected || busy || acknowledged || !state.next_step_id;
  $('acknowledge-state').textContent = acknowledged ? 'Đã xác nhận sai khác này; lần Chuẩn bị kế tiếp sẽ lưu acknowledgement trên controller.' : 'Chỉ xác nhận nếu muốn đi tiếp mà vẫn giữ nguyên sai khác; Reobserve không chạy lại thao tác backend.';
  $('completion').hidden = status !== 'complete';
  if (status === 'complete') {
    const mismatches = state.browser_observations.filter(record => record.comparison === 'mismatch').length;
    $('completion-text').textContent = `Có ${state.reference_results.length} kết quả tham chiếu, ${state.browser_observations.length} lần quan sát Chrome và ${mismatches} lần sai khác được giữ lại. Hoàn tất trình tự không đồng nghĩa mọi kết quả Chrome đều đạt.`;
  }
  $('restoration').hidden = !['complete', 'stopped'].includes(status);
  $('control-caption').textContent = busy ? 'Đang thực hiện — không gửi lại' : state?.run_id ? `Phiên ${state.run_id}` : 'Bắt đầu từ kết nối an toàn';
  $('control-help').textContent = status === 'busy' ? 'Stop tạm khóa; chờ thao tác Docker kết thúc. Dashboard có thể đóng mà không teardown.'
    : !connected ? 'Kết nối lại chỉ lấy trạng thái và đồng bộ bằng chứng, không phát lại thao tác.'
    : pending ? 'Đang chờ sự kiện/đồng bộ. unobserved không mở khóa bước sau; hãy Reobserve.'
    : remote?.comparison === 'mismatch' && !acknowledged ? 'Sai khác thật: Reobserve hoặc xác nhận rõ ràng trước bước sau.'
    : state?.next_step_id ? 'Next chỉ chọn thẻ. “Chuẩn bị” mới thực hiện thao tác lab một lần.' : 'Website được giữ tới Stop. Cấu hình Windows phải khôi phục thủ công.';
}
$('connect').addEventListener('click', () => act('connect', {token: $('pairing-token').value}));
$('pairing-token').addEventListener('keydown', event => { if (event.key === 'Enter') act('connect', {token: $('pairing-token').value}); });
$('disconnect').addEventListener('click', () => act('disconnect'));
$('forget').addEventListener('click', () => act('forget'));
$('start').addEventListener('click', () => act('start'));
$('prepare').addEventListener('click', () => act('prepare', {step_id: selectedStep(view.state)?.id}));
$('stop').addEventListener('click', () => act('stop'));
$('open-chrome').addEventListener('click', () => act('open', {step_id: selectedStep(view.state)?.id}));
$('reobserve').addEventListener('click', () => act('open', {step_id: selectedStep(view.state)?.id}));
$('next').addEventListener('click', () => act('select', {step_id: view.state?.next_step_id}));
$('acknowledge').addEventListener('click', () => act('acknowledge'));
$('reset-checklist').addEventListener('click', () => {
  const step = selectedStep(view.state);
  if (step) act('checklist', {step_id: step.id, checked: step.checklist_vi.map(() => false)});
});
$('settings-toggle').addEventListener('click', () => {
  $('settings').hidden = !$('settings').hidden;
  $('settings-toggle').setAttribute('aria-expanded', String(!$('settings').hidden));
});
window.addEventListener('pagehide', () => { closed = true; clearTimeout(timer); });
window.addEventListener('pageshow', () => { closed = false; });
await poll();
