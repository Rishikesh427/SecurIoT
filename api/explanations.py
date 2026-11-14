"""Non-blocking event explanations backed by Person C's synchronous function."""
import copy
import os
from concurrent.futures import ThreadPoolExecutor
from threading import RLock

from ml.securiot_ml.explain import explain, template


class ExplanationService:
    def __init__(self, workers=2):
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='event-explanation')
        self.lock = RLock()
        self.cache = {}
        self.pending = set()
        key = os.environ.get('GEMINI_API_KEY', '')
        model = os.environ.get('GEMINI_MODEL', '')
        self.configured = bool(key and model and not key.startswith('PASTE_') and not model.startswith('PASTE_'))

    def decorate(self, events, devices):
        by_mac = {d['mac']: d for d in devices}
        output = []
        for event in events:
            item = copy.deepcopy(event)
            key = str(item['id'])
            device = by_mac.get(item['mac'], {})
            fallback = template(item, device)
            with self.lock:
                cached = copy.deepcopy(self.cache.get(key))
                if cached is None and self.configured and key not in self.pending:
                    self.pending.add(key)
                    self.pool.submit(self._generate, key, copy.deepcopy(item), copy.deepcopy(device), fallback)
            item['explanation'] = cached or fallback
            item['explanation_status'] = 'ready' if cached else ('pending' if self.configured else 'template')
            output.append(item)
        return output

    def _generate(self, key, event, device, fallback):
        try:
            result = explain(event, device)
            if not isinstance(result, dict) or not all(isinstance(result.get(k), str) and result[k].strip()
                                                       for k in ('plain_language', 'recommended_next_step')):
                result = fallback
        except Exception:
            result = fallback
        with self.lock:
            self.cache[key] = copy.deepcopy(result)
            self.pending.discard(key)

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)
