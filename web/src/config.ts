export const mockMode = import.meta.env.VITE_MOCK_MODE === 'true';
export const apiBase = (import.meta.env.VITE_API_URL || '/api').replace(/\/+$/, '');
export const apiUrl = (path: string) => `${apiBase}/${path.replace(/^\/+/, '')}`;
