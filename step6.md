# Step 6: Refactor into Modular Structure

## Summary

Refactored the monolithic `token_sys.py` (335 lines) into a clean modular package structure with separate concerns for configuration, token generation, and token verification.

## Files Created

- `token_system/__init__.py` - Package initialization and public API exports
- `token_system/config.py` - Configuration constants and secret key management
- `token_system/generation.py` - Token generation logic
- `token_system/verification.py` - Token verification logic with replay protection

## Files Modified

- `token_sys.py` - Converted to backward compatibility wrapper that imports from new modular structure

## Code Changes

### Old Structure (token_sys.py - 335 lines)

```
token_sys.py (monolithic)
├── Configuration constants (lines 7-21)
├── Global state variables (lines 23-27)
├── Helper functions (_cleanup_old_tokens, _is_token_replayed)
├── get_time_window()
├── generate_token()
├── verify_token()
└── Test code (lines 222-335)
```

### New Structure (modular package)

```
token_system/
├── __init__.py (public API exports)
├── config.py (configuration only)
├── generation.py (token creation)
└── verification.py (token validation + replay protection)
```

### Key Changes

**1. config.py** - Extracted all configuration:
```python
WINDOW_SIZE_SECONDS = 10
VALIDATION_WINDOW = 1
MAX_TOKEN_LIFETIME_SECONDS = 300
CLOCK_SKEW_TOLERANCE_SECONDS = 15
ENABLE_REPLAY_PROTECTION = True
REPLAY_CACHE_CLEANUP_SECONDS = 60

def get_default_secret_key():
    return "my_super_secret_key"
```

**2. generation.py** - Extracted token generation:
```python
def get_time_window(timestamp=None):
    # Time window calculation logic

def generate_token(user_id, secret_key, max_lifetime_seconds=None):
    # Token generation logic with HMAC signing
```

**3. verification.py** - Extracted verification and replay protection:
```python
# Module-level state for replay cache
_used_tokens = {}
_cache_lock = threading.Lock()
_last_cleanup = 0

def _cleanup_old_tokens():
    # Replay cache cleanup

def _is_token_replayed(token):
    # Replay detection

def verify_token(token, secret_key, validation_window=None, clock_skew_tolerance=None, check_replay=None):
    # Comprehensive verification logic
```

**4. __init__.py** - Clean public API:
```python
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
```

**5. token_sys.py** - Backward compatibility wrapper:
```python
# DEPRECATED: This file is kept for backward compatibility.
# New code should use the modular token_system package.
# from token_system import generate_token, verify_token, get_time_window

from token_system import generate_token, verify_token, get_time_window
```

## Why Modularization Helps

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
   - `config.py`: Configuration management
   - `generation.py`: Token creation
   - `verification.py`: Token validation

2. **Testability**: Individual modules can be tested in isolation
   - Can mock config for testing different configurations
   - Can test generation without verification logic
   - Can test verification with controlled token generation

3. **Maintainability**: Changes to one concern don't affect others
   - Changing configuration values only touches `config.py`
   - Modifying signature algorithm only affects `generation.py`
   - Replay protection logic is isolated in `verification.py`

4. **Reusability**: Modules can be imported independently
   - Can use `generation.py` alone for token creation
   - Can use `verification.py` alone for validation
   - Configuration can be shared across different implementations

5. **Scalability**: Easy to add new features without bloating single file
   - Can add `token_system/storage.py` for persistent replay cache
   - Can add `token_system/api.py` for API layer
   - Can add `token_system/utils.py` for helper functions

## Before vs After System Behavior

### Before (Monolithic)
- Single file with 335 lines mixing concerns
- Hard to locate specific functionality
- Difficult to test individual components
- Changes risk breaking unrelated code
- No clear public API surface

### After (Modular)
- Clean package structure with 4 focused files
- Clear separation: config, generation, verification
- Each module can be tested independently
- Changes are isolated to specific modules
- Well-defined public API via `__init__.py`
- Backward compatibility maintained via wrapper

## Usage Examples

### Old usage (still works):
```python
from token_sys import generate_token, verify_token
token = generate_token("user_123", "secret")
```

### New usage (recommended):
```python
from token_system import generate_token, verify_token
token = generate_token("user_123", "secret")
```

### Importing specific modules:
```python
from token_system.generation import generate_token
from token_system.verification import verify_token
from token_system.config import WINDOW_SIZE_SECONDS
```
