"""Non-blocking event explanations with bounded work, deadlines and retry cache."""
import copy
import logging
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from threading import RLock

from ml.securiot_ml.gemini import configured
from ml.securiot_ml.explain import cache_key, explain, template, validate

logger = logging.getLogger(__name__)


class ExplanationService:
    RETRY = 60
    TTL = 3600
    DEADLINE = 8

    def __init__(self, workers=2, max_pending=4, max_cache=512):
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='event-explanation')
        self.lock = RLock()
        self.cache = OrderedDict()
        self.pending = {}
        self.configured = configured()
        self.max_pending, self.max_cache = max_pending, max_cache
        self.closed = False

    def _put(self, key, result, generated):
        self.cache[key] = (time.monotonic() + (self.TTL if generated else self.RETRY), result, generated)
        self.cache.move_to_end(key)
        while len(self.cache) > self.max_cache:
            self.cache.popitem(last=False)

    def decorate(self, events, devices):
        by_mac = {d['mac']: d for d in devices}
        output = []
        for event in events:
            item = copy.deepcopy(event)
            device = by_mac.get(event['mac'], {})
            result, status = template(event, device), 'template'
            if event['kind'] == 'volume':
                item.update(explanation=result, explanation_status=status)
                output.append(item)
                continue
            key = cache_key(event, device)
            with self.lock:
                now = time.monotonic()
                cached = self.cache.get(key)
                if cached and cached[0] <= now:
                    self.cache.pop(key)
                    cached = None
                if cached:
                    self.cache.move_to_end(key)
                    result, status = cached[1], 'ready' if cached[2] else 'template'
                elif key in self.pending:
                    # Expired work stays counted until it exits. Never replace a
                    # stalled call with unbounded new threads or block HTTP reads.
                    if now < self.pending[key]: status = 'pending'
                elif self.configured and not self.closed and len(self.pending) < self.max_pending:
                    deadline = now + self.DEADLINE
                    self.pending[key] = deadline
                    try:
                        self.pool.submit(self._generate, key, copy.deepcopy(event), copy.deepcopy(device), deadline)
                        status = 'pending'
                    except RuntimeError:
                        self.pending.pop(key, None)
            item.update(explanation=copy.deepcopy(result), explanation_status=status)
            output.append(item)
        return output

    def _generate(self, key, event, device, deadline):
        result, generated = template(event, device), False
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0: return
            candidate = validate(explain(event, device, fallback=False, timeout=min(6, remaining)))
            if time.monotonic() < deadline:
                result, generated = candidate, True
        except Exception as exc:
            logger.warning('Event explanation failed (%s); serving template', type(exc).__name__)
        finally:
            with self.lock:
                self._put(key, result, generated)
                self.pending.pop(key, None)

    def close(self):
        with self.lock: self.closed = True
        self.pool.shutdown(wait=False, cancel_futures=True)
        with self.lock: self.pending.clear()
