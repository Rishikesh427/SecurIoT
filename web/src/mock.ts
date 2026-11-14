import fixtures from '../../contract/fixtures.json';

const token = 'fixture-demo-session';
const user = { id: '00000000-0000-4000-8000-000000000001', username: 'demo', role: 'judge' };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {status, headers: {'Content-Type':'application/json'}});

/** Local fixture transport: no requests, secrets, or writes to the backend. */
export async function mockFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const route = path.split('?')[0];
  if (route === '/auth/login' && options.method === 'POST') {
    const credentials = JSON.parse(String(options.body));
    return credentials.username === 'demo' && credentials.password === 'demo'
      ? json({access_token: token}) : json({detail:'Invalid demo credentials'}, 401);
  }
  if (route === '/storage') return json({mode:'memory'});
  if (new Headers(options.headers).get('Authorization') !== `Bearer ${token}`) return json({}, 401);
  if (route === '/auth/me') return json(user);
  if (options.method && options.method !== 'GET') return json({detail:'Mock mode is read-only'}, 405);
  if (route === '/devices') return json(fixtures.devices);
  if (route === '/events') {
    const query = new URLSearchParams(path.split('?')[1]);
    const offset = Math.max(0, Number(query.get('offset') || 0));
    const limit = Math.min(1000, Math.max(1, Number(query.get('limit') || 100)));
    return json([...fixtures.events].sort((a,b) => b.ts.localeCompare(a.ts)).slice(offset, offset + limit));
  }
  return json({detail:'Mock route not found'}, 404);
}
