# Step 8: Add Logging and Monitoring Basics

## Summary

Added comprehensive logging to the token system to track token generation, successful verifications, and failed verifications. Logging provides visibility into system operations and aids in debugging and security monitoring.

## Files Created

- `token_system/logger.py` - Logging configuration and setup

## Files Modified

- `token_system/generation.py` - Added logging for token generation
- `token_system/verification.py` - Added logging for verification outcomes (success and failures)

## Code Changes

### New File: token_system/logger.py

```python
import logging
import sys
from typing import Optional


def setup_logger(name: str = "token_system", level: int = logging.INFO) -> logging.Logger:
    """Set up a logger with consistent formatting.
    
    Args:
        name: Logger name
        level: Logging level (default: INFO)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    
    # Format: timestamp - level - message
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger


# Default logger instance
logger = setup_logger()
```

### Modified: token_system/generation.py

**Added import:**
```python
from .logger import logger
```

**Added logging in generate_token():**
```python
# Log token generation
logger.info(
    f"Token generated - user_id={user_id}, "
    f"time_window={time_window}, "
    f"expiration={expiration_time}, "
    f"lifetime={max_lifetime_seconds}s"
)
```

### Modified: token_system/verification.py

**Added import:**
```python
from .logger import logger
```

**Added logging for signature failure:**
```python
if not hmac.compare_digest(encoded_signature, expected_encoded_signature):
    logger.warning(f"Token verification failed - signature mismatch")
    return False, "Signature verification failed"
```

**Added logging for expiration failure:**
```python
if current_time > adjusted_expiration:
    logger.warning(
        f"Token verification failed - expired: "
        f"user_id={user_id}, expired_at={expiration_time}, current={current_time}"
    )
    return False, f"Token expired (expired at {expiration_time}, current time {current_time})"
```

**Added logging for window expiration:**
```python
if window_diff > validation_window:
    logger.warning(
        f"Token verification failed - window expired: "
        f"user_id={user_id}, window_diff={window_diff}, allowed={validation_window}"
    )
    return False, f"Token window expired (difference: {window_diff} windows, allowed: {validation_window})"
```

**Added logging for future token (clock skew):**
```python
if token_window > current_window + (clock_skew_tolerance // WINDOW_SIZE_SECONDS):
    logger.warning(
        f"Token verification failed - future token: "
        f"user_id={user_id}, token_window={token_window}, current={current_window}"
    )
    return False, f"Token from future (clock skew too large: {token_window - current_window} seconds)"
```

**Added logging for replay attack:**
```python
if check_replay and _is_token_replayed(token):
    logger.warning(
        f"Token verification failed - replay attack: user_id={user_id}"
    )
    return False, "Token already used (replay attack detected)"
```

**Added logging for successful verification:**
```python
# Log successful verification
logger.info(
    f"Token verified successfully - user_id={user_id}, "
    f"window_diff={window_diff}, "
    f"time_until_expiration={result.get('time_until_expiration', 'N/A')}"
)
```

## Where Logging is Inserted in Code

1. **token_system/generation.py** - Line 74-79 (after token creation, before return)
2. **token_system/verification.py** - Line 122 (signature mismatch)
3. **token_system/verification.py** - Line 151-154 (token expired)
4. **token_system/verification.py** - Line 165-168 (window expired)
5. **token_system/verification.py** - Line 173-176 (future token)
6. **token_system/verification.py** - Line 181-183 (replay attack)
7. **token_system/verification.py** - Line 198-202 (successful verification)

## What Log Messages Look Like

### Token Generation (INFO level)
```
2026-04-26 08:52:00 - token_system - INFO - Token generated - user_id=user_123, time_window=1714382600, expiration=1714388900, lifetime=300s
```

### Successful Verification (INFO level)
```
2026-04-26 08:52:05 - token_system - INFO - Token verified successfully - user_id=user_123, window_diff=0, time_until_expiration=295
```

### Signature Mismatch (WARNING level)
```
2026-04-26 08:52:10 - token_system - WARNING - Token verification failed - signature mismatch
```

### Token Expired (WARNING level)
```
2026-04-26 08:52:15 - token_system - WARNING - Token verification failed - expired: user_id=user_123, expired_at=1714388500, current=1714388510
```

### Window Expired (WARNING level)
```
2026-04-26 08:52:20 - token_system - WARNING - Token verification failed - window expired: user_id=user_123, window_diff=3, allowed=1
```

### Future Token (WARNING level)
```
2026-04-26 08:52:25 - token_system - WARNING - Token verification failed - future token: user_id=user_123, token_window=1714382660, current=1714382600
```

### Replay Attack (WARNING level)
```
2026-04-26 08:52:30 - token_system - WARNING - Token verification failed - replay attack: user_id=user_456
```

## Why Each Log is Useful

### Token Generation Log
- **What it captures**: user_id, time_window, expiration time, lifetime
- **Why useful**: 
  - Tracks token creation patterns
  - Helps identify unusual token generation spikes
  - Enables auditing of who received tokens and when
  - Useful for debugging token lifecycle issues

### Successful Verification Log
- **What it captures**: user_id, window_diff, time_until_expiration
- **Why useful**:
  - Confirms tokens are being used correctly
  - Shows how often tokens are verified
  - Helps identify token refresh patterns
  - Validates that expiration logic is working

### Signature Mismatch Log
- **What it captures**: Failure reason only
- **Why useful**:
  - Indicates potential tampering attempts
  - Could signal secret key mismatch
  - Helps detect malformed tokens
  - Security monitoring for attack patterns

### Token Expired Log
- **What it captures**: user_id, expired_at, current time
- **Why useful**:
  - Confirms expiration logic is working
  - Helps identify clock skew issues
  - Shows if tokens are being used too late
  - Useful for tuning lifetime parameters

### Window Expired Log
- **What it captures**: user_id, window_diff, allowed windows
- **Why useful**:
  - Validates time window logic
  - Helps identify network latency issues
  - Shows if validation_window is too strict
  - Useful for tuning window parameters

### Future Token Log
- **What it captures**: user_id, token_window, current_window
- **Why useful**:
  - Detects clock skew problems
  - Could indicate client time manipulation
  - Helps tune clock_skew_tolerance
  - Security monitoring for time-based attacks

### Replay Attack Log
- **What it captures**: user_id
- **Why useful**:
  - Critical security alert
  - Detects token reuse attempts
  - Helps identify attack patterns
  - Confirms replay protection is working

## Before vs After System Behavior

### Before (Step 7)
- No visibility into token operations
- Difficult to debug issues in production
- No security event tracking
- Silent failures make troubleshooting hard
- No audit trail for token usage

### After (Step 8)
- Complete visibility into all token operations
- Easy to debug issues with detailed logs
- Security events are logged (replay attacks, tampering)
- Structured log format with timestamps
- Audit trail for compliance and monitoring
- Can integrate with log aggregation tools (ELK, Splunk, etc.)
- Can set up alerts on WARNING level logs for security events

## Log Levels Used

- **INFO**: Normal operations (token generation, successful verification)
- **WARNING**: Security-relevant failures (signature mismatch, replay attack, expiration issues)

This allows setting up alerts on WARNING logs while keeping INFO logs for operational monitoring.
