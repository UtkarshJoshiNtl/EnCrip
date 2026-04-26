"""Configuration module for token system.

Handles all configuration constants and secret key management.
"""

# Time window configuration
WINDOW_SIZE_SECONDS = 10  # Tokens rotate every 10 seconds
VALIDATION_WINDOW = 1     # Allow tokens from ±1 window (±10 seconds)

# Token expiration configuration
MAX_TOKEN_LIFETIME_SECONDS = 300  # Maximum absolute token lifetime (5 minutes)
                                    # Prevents tokens from being valid indefinitely even with window rotation

# Clock skew tolerance
CLOCK_SKEW_TOLERANCE_SECONDS = 15  # Allow clock skew up to 15 seconds
                                    # Accommodates client-server clock differences

# Replay protection configuration
ENABLE_REPLAY_PROTECTION = True    # Enable/disable replay protection
REPLAY_CACHE_CLEANUP_SECONDS = 60  # Clean up old entries every 60 seconds


def get_default_secret_key():
    """Get the default secret key for development.
    
    WARNING: In production, load this from environment variables or secure vault.
    """
    return "my_super_secret_key"
