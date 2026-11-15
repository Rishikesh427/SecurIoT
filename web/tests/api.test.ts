import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const policy={learning_mode:false,protected_macs:[],ladder:{notify:true,block_wan:true,quarantine:true}};
beforeEach(()=>{vi.resetModules();vi.stubEnv('VITE_USE_MOCK','false');localStorage.clear();});
afterEach(()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();});

it('sends authenticated quarantine and restore requests with idempotency keys',async()=>{
  const fetch=vi.fn().mockResolvedValue(new Response(JSON.stringify({id:'command-1'}),{headers:{'Content-Type':'application/json'}}));
  vi.stubGlobal('fetch',fetch);
  const {api,setToken}=await import('../src/api/client'); setToken('test-session');
  await api.action({action:'quarantine',mac:'02:00:00:00:00:20'});
  const [url,options]=fetch.mock.calls[0];
  expect(url).toBe('/api/actions?wait=true');
  expect(options.headers.Authorization).toBe('Bearer test-session');
  expect(options.headers['Idempotency-Key']).toMatch(/^[0-9a-f-]{36}$/);
  expect(JSON.parse(options.body)).toEqual({action:'quarantine',mac:'02:00:00:00:00:20'});
  fetch.mockResolvedValue(new Response('{}',{headers:{'Content-Type':'application/json'}}));
  await api.action({action:'restore',mac:'02:00:00:00:00:20'});
  expect(JSON.parse(fetch.mock.calls[1][1].body).action).toBe('restore');
});

it('uses the policy version so stale settings cannot overwrite other protection',async()=>{
  const fetch=vi.fn().mockImplementation(async(_url,options)=>new Response(JSON.stringify(policy),{
    status:options.method==='PUT'?412:200,headers:{'Content-Type':'application/json','ETag':'"revision-1"'}}));
  vi.stubGlobal('fetch',fetch);
  const {api}=await import('../src/api/client');
  await api.policy();
  await expect(api.savePolicy({...policy,learning_mode:true})).rejects.toThrow();
  expect(fetch.mock.calls[1][1].headers['If-Match']).toBe('"revision-1"');
});
