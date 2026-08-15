from collections import defaultdict
from threading import Lock
from time import time


request_history = defaultdict(list)
history_lock = Lock()


def is_rate_limited(
    identifier: str,
    limit: int,
    window_seconds: int
) -> bool:
    current_time = time()
    window_start = current_time - window_seconds

    with history_lock:
        recent_requests = [
            request_time
            for request_time in request_history[identifier]
            if request_time > window_start
        ]

        request_history[identifier] = recent_requests

        if len(recent_requests) >= limit:
            return True

        request_history[identifier].append(current_time)
        return False