import { test, expect } from 'vitest';
import { mockFetch } from './mock';
import fixtures from '../../contract/fixtures.json';
test('mock login rejects bad credentials and permits fixture reads', async () => {
  expect((await mockFetch('/devices')).status).toBe(401);
  expect((await mockFetch('/auth/login', {method:'POST',body:JSON.stringify({username:'judge',password:'wrong'})})).status).toBe(401);
  const login = await (await mockFetch('/auth/login', {method:'POST',body:JSON.stringify({username:'demo',password:'demo'})})).json();
  const headers = {Authorization:`Bearer ${login.access_token}`};
  expect(await (await mockFetch('/devices',{headers})).json()).toEqual(fixtures.devices);
  const events = await (await mockFetch('/events?limit=1',{headers})).json();
  expect(events).toHaveLength(1);
  expect(events[0].kind).toBe('decoy_touch');
  expect((await mockFetch('/actions',{headers,method:'POST'})).status).toBe(405);
});
