import hmac       # Used to create the cryptographic signature
import hashlib    # Provides the hashing algorithms like SHA256
import base64     # Used to safely encode the bytes into string format
import time       # Used to generate timestamps

# Time window configuration
WINDOW_SIZE_SECONDS = 10  # Tokens rotate every 10 seconds
VALIDATION_WINDOW = 1     # Allow tokens from ±1 window (±10 seconds)

# Token expiration configuration
MAX_TOKEN_LIFETIME_SECONDS = 300  # Maximum absolute token lifetime (5 minutes)
                                    # Prevents tokens from being valid indefinitely even with window rotation

# Clock skew tolerance
CLOCK_SKEW_TOLERANCE_SECONDS = 15  # Allow clock skew up to 15 seconds
                                    # Accommodates client-server clock differences

def get_time_window(timestamp=None):
    """Calculate the time window for a given timestamp (or current time)."""
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
        str: The generated token string
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
    return token

def verify_token(token, secret_key, validation_window=None, clock_skew_tolerance=None):
    """Verify a token with comprehensive expiration and clock skew checks.
    
    Args:
        token: The token string to verify
        secret_key: The secret key used for signature verification
        validation_window: Number of adjacent windows to allow (default: VALIDATION_WINDOW)
                          If set to 1, allows current window ±1 (total 3 windows)
        clock_skew_tolerance: Clock skew tolerance in seconds (default: CLOCK_SKEW_TOLERANCE_SECONDS)
    
    Returns:
        (bool, dict|string): True with user data if valid, False with error message if invalid
    """
    if validation_window is None:
        validation_window = VALIDATION_WINDOW
    if clock_skew_tolerance is None:
        clock_skew_tolerance = CLOCK_SKEW_TOLERANCE_SECONDS
    
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

# Quick test execution
if __name__ == "__main__":
    test_secret = "my_super_secret_key"
    
    print("=== Enhanced Token System Demo ===\n")
    
    # Test 1: Generate and verify a token with expiration
    print("--- Test 1: Generate and verify with expiration ---")
    my_token = generate_token("user_123", test_secret)
    print(f"Generated Token: {my_token}")
    is_valid, data = verify_token(my_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 2: Token with custom short lifetime
    print("--- Test 2: Token with short lifetime (2 seconds) ---")
    short_token = generate_token("user_123", test_secret, max_lifetime_seconds=2)
    print(f"Short-lived Token: {short_token}")
    is_valid, data = verify_token(short_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}")
    print("Waiting 3 seconds...")
    time.sleep(3)
    is_valid, data = verify_token(short_token, test_secret)
    print(f"After 3s - Valid: {is_valid} | Data: {data}\n")
    
    # Test 3: Clock skew tolerance (future token)
    print("--- Test 3: Clock skew tolerance (future token) ---")
    current_window = get_time_window()
    future_window = current_window + 30  # 30 seconds in future
    future_payload = f"user_123:{future_window}:{int(time.time()) + 300}"
    future_encoded_payload = base64.urlsafe_b64encode(future_payload.encode('utf-8')).rstrip(b'=')
    future_signature = hmac.new(
        key=test_secret.encode('utf-8'),
        msg=future_encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    future_encoded_signature = base64.urlsafe_b64encode(future_signature).rstrip(b'=')
    future_token = f"{future_encoded_payload.decode('utf-8')}.{future_encoded_signature.decode('utf-8')}"
    print(f"Future Token (30s ahead): {future_token}")
    is_valid, data = verify_token(future_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 4: Old token format backward compatibility
    print("--- Test 4: Backward compatibility (old token format) ---")
    old_format_window = get_time_window()
    old_format_payload = f"user_123:{old_format_window}"
    old_format_encoded_payload = base64.urlsafe_b64encode(old_format_payload.encode('utf-8')).rstrip(b'=')
    old_format_signature = hmac.new(
        key=test_secret.encode('utf-8'),
        msg=old_format_encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    old_format_encoded_signature = base64.urlsafe_b64encode(old_format_signature).rstrip(b'=')
    old_format_token = f"{old_format_encoded_payload.decode('utf-8')}.{old_format_encoded_signature.decode('utf-8')}"
    print(f"Old Format Token: {old_format_token}")
    is_valid, data = verify_token(old_format_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 5: Expired token (absolute expiration)
    print("--- Test 5: Expired token (absolute expiration) ---")
    expired_payload = f"user_123:{get_time_window()}:{int(time.time()) - 10}"  # Expired 10s ago
    expired_encoded_payload = base64.urlsafe_b64encode(expired_payload.encode('utf-8')).rstrip(b'=')
    expired_signature = hmac.new(
        key=test_secret.encode('utf-8'),
        msg=expired_encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    expired_encoded_signature = base64.urlsafe_b64encode(expired_signature).rstrip(b'=')
    expired_token = f"{expired_encoded_payload.decode('utf-8')}.{expired_encoded_signature.decode('utf-8')}"
    print(f"Expired Token: {expired_token}")
    is_valid, data = verify_token(expired_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 6: Token from previous window (within validation window)
    print("--- Test 6: Token from previous window (valid) ---")
    prev_window = get_time_window() - WINDOW_SIZE_SECONDS
    prev_payload = f"user_123:{prev_window}:{int(time.time()) + 300}"
    prev_encoded_payload = base64.urlsafe_b64encode(prev_payload.encode('utf-8')).rstrip(b'=')
    prev_signature = hmac.new(
        key=test_secret.encode('utf-8'),
        msg=prev_encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    prev_encoded_signature = base64.urlsafe_b64encode(prev_signature).rstrip(b'=')
    prev_token = f"{prev_encoded_payload.decode('utf-8')}.{prev_encoded_signature.decode('utf-8')}"
    print(f"Previous Window Token: {prev_token}")
    is_valid, data = verify_token(prev_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 7: Invalid signature
    print("--- Test 7: Invalid signature (tampered token) ---")
    tampered_token = my_token[:-5] + "xxxxx"
    print(f"Tampered Token: {tampered_token}")
    is_valid, data = verify_token(tampered_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    print("=== Demo Complete ===")
