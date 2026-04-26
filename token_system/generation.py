"""Token generation module.

Handles creation of HMAC-based time-windowed tokens with expiration.
"""

import hmac
import hashlib
import base64
import time

from .config import (
    WINDOW_SIZE_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS
)
from .logger import logger


def get_time_window(timestamp=None):
    """Calculate the time window for a given timestamp (or current time).
    
    Args:
        timestamp: Unix timestamp (optional, defaults to current time)
    
    Returns:
        int: The time window (floored to nearest WINDOW_SIZE_SECONDS)
    """
    if timestamp is None:
        timestamp = int(time.time())
    # Floor to the nearest 10-second window
    return (timestamp // WINDOW_SIZE_SECONDS) * WINDOW_SIZE_SECONDS


def generate_token(user_id, secret_key, max_lifetime_seconds=None):
    """Generate a time-based token with absolute expiration.
    
    Args:
        user_id: The user identifier to embed in the token
        secret_key: The secret key for HMAC signature
        max_lifetime_seconds: Override default max lifetime (optional)
    
    Returns:
        str: The generated token string in format: base64(payload).base64(signature)
    """
    # Get current time window instead of exact timestamp
    time_window = get_time_window()
    
    # Calculate absolute expiration time
    if max_lifetime_seconds is None:
        max_lifetime_seconds = MAX_TOKEN_LIFETIME_SECONDS
    expiration_time = int(time.time()) + max_lifetime_seconds
    
    # Create the payload string joining user_id, time window, and expiration
    payload = f"{user_id}:{time_window}:{expiration_time}"
    
    # Encode the payload to URL-safe base64 (removes '=' padding for cleaner URLs)
    encoded_payload = base64.urlsafe_b64encode(payload.encode('utf-8')).rstrip(b'=')
    
    # Generate the HMAC signature using SHA256
    # key must be bytes, so we encode the secret string
    # msg also must be bytes, we use our encoded payload
    signature = hmac.new(
        key=secret_key.encode('utf-8'),
        msg=encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    
    # Encode the signature bytes to URL-safe base64 as well
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')
    
    # Combine payload and signature with a single dot '.' delimiter to form the final token
    token = f"{encoded_payload.decode('utf-8')}.{encoded_signature.decode('utf-8')}"
    
    # Log token generation
    logger.info(
        f"Token generated - user_id={user_id}, "
        f"time_window={time_window}, "
        f"expiration={expiration_time}, "
        f"lifetime={max_lifetime_seconds}s"
    )
    
    return token
