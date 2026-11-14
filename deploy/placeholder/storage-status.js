const statusLabel = document.getElementById('storage-status');
const detail = document.getElementById('storage-detail');
const retry = document.getElementById('storage-retry');
let pending = false;
async function checkStorage() {
  if (pending) return;
  pending = true;
  retry.disabled = true;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch('/api/storage', { cache: 'no-store', signal: controller.signal });
    if (!response.ok) throw new Error('Storage unavailable');
    const storage = await response.json();
    if (!['memory', 'postgres'].includes(storage.mode)) throw new Error('Invalid status');
    statusLabel.dataset.mode = storage.mode;
    statusLabel.textContent = storage.mode === 'memory' ? 'Demo storage' : 'Tiger Data connected';
    detail.textContent = storage.mode === 'memory'
      ? 'Changes are temporary and disappear when the API restarts. Save any demo results before restarting.'
      : 'Device reports and commands are stored in the database.';
  } catch {
    delete statusLabel.dataset.mode;
    statusLabel.textContent = 'Storage status unavailable';
    detail.textContent = 'The API could not confirm storage. Check that it is running, then try again.';
  } finally {
    clearTimeout(timer);
    retry.disabled = false;
    pending = false;
  }
}
retry.addEventListener('click', checkStorage);
checkStorage();
setInterval(() => { if (!document.hidden) checkStorage(); }, 10000);
