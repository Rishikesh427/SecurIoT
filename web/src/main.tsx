import { createRoot } from 'react-dom/client';
import App from './App';
import './dashboard.css';
import './tailwind.css';
import { mockMode } from './config';

createRoot(document.getElementById('root')!).render(<>{mockMode && <div role="status" className="border-b border-amber-300 bg-amber-50 px-6 py-3 text-sm text-amber-950"><strong>Offline fixture demo</strong> · Sign in with username <b>demo</b> and password <b>demo</b>. No API or hardware required.</div>}<App /></>);
