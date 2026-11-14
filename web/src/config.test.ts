import { afterEach, expect, test, vi } from 'vitest';
afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });
test('API base applies to every transport request including storage', async () => {
  vi.stubEnv('VITE_API_URL', 'https://example.test/api/');
  vi.stubEnv('VITE_MOCK_MODE', 'false'); vi.resetModules();
  const {transport} = await import('./api');
  const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response('{}'));
  await transport('/storage', {}, fetchImpl);
  expect(fetchImpl.mock.calls[0][0]).toBe('https://example.test/api/storage');
});
test('mock client authenticates and loads fixtures without network calls', async () => {
  vi.stubEnv('VITE_MOCK_MODE', 'true'); vi.resetModules();
  const {createApiClient} = await import('./api');
  const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new Error('Must not access network'));
  const client = createApiClient({fetchImpl});
  expect((await client.login('demo','demo')).username).toBe('demo');
  expect(await client.request('/devices')).toHaveLength(3);
  expect(fetchImpl).not.toHaveBeenCalled();
  client.logout();
  await expect(client.request('/events')).rejects.toMatchObject({status:401});
});
