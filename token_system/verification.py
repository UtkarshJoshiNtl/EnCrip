"""Token verification module.

Handles verification of HMAC-based tokens with expiration, clock skew, and replay protection.
"""

import hmac
import hashlib
import base64
import time
import threading

from .config import (
    VALIDATION_WINDOW,
    CLOCK_SKEW_TOLERANCE_SECONDS,
    ENABLE_REPLAY_PROTECTION,
    REPLAY_CACHE_CLEANUP_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS
)
from .generation import get_time_window


# Simple in-memory token cache for replay protection
# Format: {token_hash: first_seen_timestamp}
_used_tokens = {}
_cache_lock = threading.Lock()
_last_cleanup = 0


def _cleanup_old_tokens():
    """Remove expired tokens from the replay cache."""
    global _last_cleanup
    current_time = int(time.time())
    
    # Only run cleanup periodically
    if current_time - _last_cleanup < REPLAY_CACHE_CLEANUP_SECONDS:
        return
    
    with _cache_lock:
        # Remove tokens older than MAX_TOKEN_LIFETIME_SECONDS
        cutoff_time = current_time - MAX_TOKEN_LIFETIME_SECONDS
        expired_tokens = [
            token_hash for token_hash, seen_time in _used_tokens.items()
            if seen_time < cutoff_time
        ]
        for token_hash in expired_tokens:
            del _used_tokens[token_hash]
        
        _last_cleanup = current_time


def _is_token_replayed(token):
    """Check if token has been used before (replay detection).
    
    Args:
        token: The token string to check
    
    Returns:
        bool: True if token was already used, False otherwise
    """
    if not ENABLE_REPLAY_PROTECTION:
        return False
    
    # Create a hash of the token for storage (don't store full token)
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    with _cache_lock:
        # Run cleanup periodically
        _cleanup_old_tokens()
        
        # Check if token was already used
        if token_hash in _used_tokens:
            return True
        
        # Mark token as used
        _used_tokens[token_hash] = int(time.time())
        return False


def verify_token(token, secret_key, validation_window=None, clock_skew_tolerance=None, check_replay=None):
    """Verify a token with comprehensive expiration, clock skew, and replay checks.
    
    Args:
        token: The token string to verify
        secret_key: The secret key used for signature verification
        validation_window: Number of adjacent windows to allow (default: VALIDATION_WINDOW)
                          If set to 1, allows current window ±1 (total 3 windows)
        clock_skew_tolerance: Clock skew tolerance in seconds (default: CLOCK_SKEW_TOLERANCE_SECONDS)
        check_replay: Enable replay check (default: ENABLE_REPLAY_PROTECTION)
    
    Returns:
        (bool, dict|string): True with user data if valid, False with error message if invalid
    """
    if validation_window is None:
        validation_window = VALIDATION_WINDOW
    if clock_skew_tolerance is None:
        clock_skew_tolerance = CLOCK_SKEW_TOLERANCE_SECONDS
    if check_replay is None:
        check_replay = ENABLE_REPLAY_PROTECTION
    
    current_time = int(time.time())
    
    # Ensure the token has exactly one dot delimiter separating payload and signature
    if token.count('.') != 1:
        return False, "Invalid token format"
        
    # Split the string token into payload and signature parts
    encoded_payload, encoded_signature = token.split('.')
    
    # Re-calculate what the signature SHOULD be, using the provided payload and our secret key
    expected_signature = hmac.new(
        key=secret_key.encode('utf-8'),
        msg=encoded_payload.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    
    # Encode the expected signature to compare it easily against the one in the token
    expected_encoded_signature = base64.urlsafe_b64encode(expected_signature).rstrip(b'=').decode('utf-8')
    
    # SECURE COMPARISON: hmac.compare_digest prevents "timing attacks" where attackers guess the signature letter by letter
    if not hmac.compare_digest(encoded_signature, expected_encoded_signature):
        return False, "Signature verification failed"
        
    # If the signature is valid, decode the payload to check the time window and expiration
    # Add back the base64 padding '=' characters necessary for python's b64decode to work
    padding = '=' * (4 - (len(encoded_payload) % 4))
    decoded_payload_bytes = base64.urlsafe_b64decode(encoded_payload + padding)
    decoded_payload = decoded_payload_bytes.decode('utf-8')
    
    # Split the decoded string payload back into user_id, time window, and expiration
    try:
        user_id, token_window, expiration_time = decoded_payload.split(':')
        token_window = int(token_window)
        expiration_time = int(expiration_time)
    except ValueError:
        # Handle old token format (without expiration) for backward compatibility
        try:
            user_id, token_window = decoded_payload.split(':')
            token_window = int(token_window)
            expiration_time = None
        except ValueError:
            return False, "Invalid payload format"
    
    # Check absolute expiration if present (new token format)
    if expiration_time is not None:
        # Apply clock skew tolerance to expiration check
        # If client clock is behind, token might appear expired when it's still valid
        adjusted_expiration = expiration_time + clock_skew_tolerance
        if current_time > adjusted_expiration:
            return False, f"Token expired (expired at {expiration_time}, current time {current_time})"
    
    # Get current time window
    current_window = get_time_window()
    
    # Calculate the difference in windows
    window_diff = abs(current_window - token_window) // WINDOW_SIZE_SECONDS
    
    # Check if the token's window is within the allowed validation window
    if window_diff > validation_window:
        return False, f"Token window expired (difference: {window_diff} windows, allowed: {validation_window})"
    
    # Additional check: reject tokens that are too far in the future (clock skew protection)
    if token_window > current_window + (clock_skew_tolerance // WINDOW_SIZE_SECONDS):
        return False, f"Token from future (clock skew too large: {token_window - current_window} seconds)"
    
    # Check for replay attack
    if check_replay and _is_token_replayed(token):
        return False, "Token already used (replay attack detected)"
    
    # Return success along with the extracted user ID and window info
    result = {
        "user_id": user_id,
        "token_window": token_window,
        "current_window": current_window,
        "window_diff": window_diff
    }
    if expiration_time is not None:
        result["expiration_time"] = expiration_time
        result["time_until_expiration"] = expiration_time - current_time
    
    return True, result
