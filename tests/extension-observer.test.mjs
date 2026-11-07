import test from 'node:test';
import assert from 'node:assert/strict';
import {createPendingObservation, reduceObservation} from '../extension/observer.mjs';

const url = 'https://login.payroll.test/evidence?request_id=run1-chrome-revoked-nav1';
const makePending = () => createPendingObservation({run_id: 'run1', step_id: 'revoked', navigation_id: 'nav1', tab_id: 17, url});
const event = (kind, overrides = {}) => ({kind, tab_id: 17, url, request_id: 'chrome-request-9',
  status_code: null, origin: null, error: null, observed_at: '2026-11-07T09:00:00.000Z', ...overrides});

test('ignores unrelated tabs, stale nonce URLs, hosts and request identities', () => {
  const initial = makePending();
  for (const unrelated of [
    event('completed', {tab_id: 18, status_code: 200}),
    event('completed', {url: url.replace('nav1', 'old-nav'), status_code: 200}),
    event('error', {url: url.replace('login.', 'other.'), error: 'net::ERR_CERT_REVOKED'}),
    event('completed', {url: 'https://login.payroll.test/favicon.ico', status_code: 200}),
    event('completed', {request_id: null, status_code: 200}),
  ]) {
    const result = reduceObservation(initial, unrelated);
    assert.equal(result.pending, initial);
    assert.equal(result.completed, null);
  }
  const headers = reduceObservation(initial, event('headers', {status_code: 200, origin: 'attacker'}));
  const stale = reduceObservation(headers.pending, event('error', {request_id: 'old-request', error: 'net::ERR_ABORTED'}));
  assert.equal(stale.pending, headers.pending);
  assert.equal(stale.completed, null);
});

test('headers are evidence only, not a successful terminal observation', () => {
  const result = reduceObservation(makePending(), event('headers', {status_code: 200, origin: 'attacker'}));
  assert.equal(result.completed, null);
  assert.equal(result.pending.terminal, false);
  assert.equal(result.pending.status_code, 200);
  assert.equal(result.pending.origin, 'attacker');
  assert.equal(result.pending.request_id, 'chrome-request-9');
});

test('successful completion retains actual status and origin from headers', () => {
  const headers = reduceObservation(makePending(), event('headers', {status_code: 200, origin: 'attacker'}));
  const {completed} = reduceObservation(headers.pending, event('completed', {status_code: 200}));
  assert.equal(completed.outcome, 'http');
  assert.equal(completed.status_code, 200);
  assert.equal(completed.origin, 'attacker');
  assert.equal(completed.source, 'chrome.webRequest');
  assert.equal(completed.error, null);
  assert.equal(completed.url, url);
  assert.equal(completed.navigation_id, 'nav1');
  assert.equal('comparison' in completed, false);
});

test('missing and unexpected origin markers are preserved, never invented', () => {
  for (const origin of [null, 'legitimate', 'unknown', 'ATTACKER']) {
    const headers = reduceObservation(makePending(), event('headers', {status_code: 503, origin}));
    const result = reduceObservation(headers.pending, event('completed', {status_code: 503}));
    assert.equal(result.completed.origin, origin);
    assert.equal(result.completed.status_code, 503);
    assert.equal(result.completed.outcome, 'http');
    assert.equal('comparison' in result.completed, false);
  }
  const {completed} = reduceObservation(makePending(), event('completed', {status_code: 200}));
  assert.equal(completed.origin, null);
});

test('generic network errors retain exact cause and never become revoked', () => {
  for (const error of ['net::ERR_ABORTED', 'net::ERR_CONNECTION_REFUSED', 'net::ERR_NAME_NOT_RESOLVED', 'ERR_CERT_REVOKED', 'net::ERR_CERT_REVOKED']) {
    const {completed} = reduceObservation(makePending(), event('error', {error}));
    assert.equal(completed.error, error);
    assert.equal(completed.outcome, 'error');
    assert.equal(completed.status_code, null);
    assert.equal(completed.origin, null);
    assert.equal(completed.source, 'chrome.webRequest');
  }
});

test('duplicate or contradictory terminal events emit once', () => {
  const first = reduceObservation(makePending(), event('error', {error: 'net::ERR_CERT_REVOKED'}));
  for (const next of [event('error', {error: 'net::ERR_ABORTED'}), event('completed', {status_code: 200, origin: 'attacker'}), event('tab_closed'), event('timeout')]) {
    const result = reduceObservation(first.pending, next);
    assert.equal(result.pending, first.pending);
    assert.equal(result.completed, null);
  }
});

test('closure and timeout are lifecycle unobserved, not Chrome TLS evidence', () => {
  for (const kind of ['tab_closed', 'timeout']) {
    const headers = reduceObservation(makePending(), event('headers', {status_code: 200, origin: 'attacker'}));
    const {completed} = reduceObservation(headers.pending, {kind, tab_id: 17, observed_at: '2026-11-07T09:00:15.000Z'});
    assert.equal(completed.source, 'extension.lifecycle');
    assert.equal(completed.outcome, 'unobserved');
    assert.equal(completed.status_code, null);
    assert.equal(completed.origin, null);
    assert.equal(completed.error, null);
    assert.equal(completed.observed_at, '2026-11-07T09:00:15.000Z');
  }
  const unrelated = reduceObservation(makePending(), {kind: 'tab_closed', tab_id: 99});
  assert.equal(unrelated.completed, null);
});

test('an old navigation cannot overwrite a new active navigation', () => {
  const nextUrl = url.replace('nav1', 'nav2');
  const pending = createPendingObservation({run_id: 'run1', step_id: 'revoked', navigation_id: 'nav2', tab_id: 17, url: nextUrl});
  const result = reduceObservation(pending, event('completed', {status_code: 200, origin: 'attacker'}));
  assert.equal(result.pending, pending);
  assert.equal(result.completed, null);
});

test('tracked navigation validation rejects non-lab and ambiguous nonce targets', () => {
  for (const target of [url.replace('https:', 'http:'), url.replace('/evidence?', '/?'), `${url}&request_id=other`, `${url}#fragment`, url.replace('nav1', 'wrong'), url.replace('.test/', '.test:8443/'), url.replace('login.payroll.test', 'example.com')]) {
    assert.throws(() => createPendingObservation({run_id: 'run1', step_id: 'revoked', navigation_id: 'nav1', tab_id: 17, url: target}));
  }
});
