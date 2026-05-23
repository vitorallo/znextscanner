"""Retry logic with exponential backoff for transient failures."""

import time
from functools import wraps
from typing import Any, Callable, TypeVar

import structlog

log = structlog.get_logger()

F = TypeVar("F", bound=Callable[..., Any])

# Exceptions considered transient (worth retrying)
TRANSIENT_EXCEPTIONS = (
    TimeoutError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    OSError,
)


def retry_on_transient(
    max_retries: int = 3,
    base_delay: float = 2.0,
    max_delay: float = 30.0,
    transient_exceptions: tuple[type[Exception], ...] = TRANSIENT_EXCEPTIONS,
) -> Callable[[F], F]:
    """Decorator that retries a function on transient exceptions.

    Uses exponential backoff: delay = base_delay * 2^attempt, capped at max_delay.
    Non-transient exceptions (PermissionError, ValueError, etc.) are raised immediately.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception: Exception | None = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except transient_exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(base_delay * (2**attempt), max_delay)
                        log.warning(
                            "retry_transient_error",
                            attempt=attempt + 1,
                            max_retries=max_retries,
                            delay=delay,
                            error=str(e),
                            function=func.__name__,
                        )
                        time.sleep(delay)
                    else:
                        log.error(
                            "retry_exhausted",
                            attempts=max_retries + 1,
                            error=str(e),
                            function=func.__name__,
                        )

            raise last_exception  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator
