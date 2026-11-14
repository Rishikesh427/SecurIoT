/** Same-origin API client. Access tokens stay in memory and clear on reload. */
import type { User } from './types';
import { apiUrl, mockMode } from './config';

export async function transport(path: string, options: RequestInit = {}, fetchImpl: typeof fetch = fetch) {
  if (mockMode) return (await import('./mock')).mockFetch(path, options);
  return fetchImpl(apiUrl(path), options);
}
export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.status = status;
  }
}

export function createApiClient({ fetchImpl = fetch, onSessionExpired = () => {} }: { fetchImpl?: typeof fetch; onSessionExpired?: () => void } = {}) {
  let token: string | null = null;
  let generation = 0;

  function logout() {
    token = null;
    generation += 1;
  }

  async function request<T>(path: string, { authenticated = true, ...options }: RequestInit & { authenticated?: boolean } = {}): Promise<T> {
    const started = generation;
    if (authenticated && !token) throw new ApiError('Please sign in to continue.', 401);
    const headers = new Headers(options.headers);
    if (authenticated) headers.set('Authorization', `Bearer ${token}`);
    if (options.body) headers.set('Content-Type', 'application/json');
    let response;
    try {
      response = await transport(path, {
        ...options, headers, cache: 'no-store', signal: AbortSignal.timeout(15000),
      }, fetchImpl);
    } catch {
      throw new ApiError('Cannot reach SecurIoT. Check your connection and try again.');
    }
    if (started !== generation) throw new ApiError('Session changed. Please try again.');
    if (response.status === 401 && authenticated) {
      logout();
      onSessionExpired();
      throw new ApiError('Your session has expired. Please sign in again.', 401);
    }
    if (!response.ok) {
      const message = response.status === 401 ? 'Username or password is incorrect.'
        : response.status === 503 ? 'The service is temporarily unavailable. Please try again.'
        : `Request failed (${response.status}). Please try again.`;
      throw new ApiError(message, response.status);
    }
    return response.status === 204 ? null as T : response.json();
  }

  async function login(username: string, password: string): Promise<User> {
    logout();
    const started = generation;
    const result = await request<{access_token: string}>('/auth/login', {
      authenticated: false, method: 'POST', body: JSON.stringify({ username, password }),
    });
    if (started !== generation) throw new ApiError('Sign-in was cancelled. Please try again.');
    if (typeof result.access_token !== 'string' || !result.access_token) {
      throw new ApiError('The server returned an invalid session. Please try again.');
    }
    token = result.access_token;
    try { return await request<User>('/auth/me'); }
    catch (error) { if (started === generation) logout(); throw error; }
  }

  return { login, logout, request };
}
