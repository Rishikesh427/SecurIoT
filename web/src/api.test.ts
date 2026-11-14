import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createApiClient } from './api';

const json = (body, status = 200) => new Response(JSON.stringify(body), { status });

test('login verifies identity, sends bearer token, and logout clears it', async () => {
  const calls = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    calls.push([url, options]);
    return json(url.endsWith('/login') ? { access_token: 'test-token' } : { username: 'judge' });
  }});
  assert.equal((await client.login('judge', 'password')).username, 'judge');
  assert.equal(calls[0][1].headers.has('Authorization'), false);
  assert.equal(calls[1][1].headers.get('Authorization'), 'Bearer test-token');
  client.logout();
  await assert.rejects(client.request('/devices'), { status: 401 });
  assert.equal(calls.length, 2);
});

test('expired session clears credentials and notifies the UI', async () => {
  let expired = 0;
  const client = createApiClient({ onSessionExpired: () => expired++, fetchImpl: async url =>
    url.endsWith('/login') ? json({ access_token: 'token' }) :
      url.endsWith('/me') ? json({ username: 'judge' }) : json({}, 401) });
  await client.login('judge', 'password');
  await assert.rejects(client.request('/devices'), { status: 401 });
  assert.equal(expired, 1);
  await assert.rejects(client.request('/events'), { status: 401 });
  assert.equal(expired, 1);
});

test('logout during a pending login prevents stale authentication', async () => {
  let finish;
  const client = createApiClient({ fetchImpl: () => new Promise(resolve => { finish = resolve; }) });
  const pending = client.login('judge', 'password');
  client.logout();
  finish(json({ access_token: 'stale-token' }));
  await assert.rejects(pending);
  await assert.rejects(client.request('/devices'), { status: 401 });
});

test('network errors provide a recoverable message', async () => {
  const client = createApiClient({ fetchImpl: async () => { throw new Error('offline'); } });
  await assert.rejects(client.login('judge', 'password'), /Check your connection/);
});
