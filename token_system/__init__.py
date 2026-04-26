"""Token System - HMAC-based stateless token authentication.

A minimal, secure token system with:
- Time-windowed tokens (10-second rotation)
- Absolute expiration (5-minute max lifetime)
- Clock skew tolerance (15 seconds)
- Replay attack protection
"""

from .config import (
    WINDOW_SIZE_SECONDS,
    VALIDATION_WINDOW,
    MAX_TOKEN_LIFETIME_SECONDS,
    CLOCK_SKEW_TOLERANCE_SECONDS,
    ENABLE_REPLAY_PROTECTION,
    get_default_secret_key
)
from .generation import generate_token, get_time_window
from .verification import verify_token

__all__ = [
    'WINDOW_SIZE_SECONDS',
    'VALIDATION_WINDOW',
    'MAX_TOKEN_LIFETIME_SECONDS',
    'CLOCK_SKEW_TOLERANCE_SECONDS',
    'ENABLE_REPLAY_PROTECTION',
    'get_default_secret_key',
    'generate_token',
    'get_time_window',
    'verify_token'
]
