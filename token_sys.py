import hmac       # Used to create the cryptographic signature
import hashlib    # Provides the hashing algorithms like SHA256
import base64     # Used to safely encode the bytes into string format
import time       # Used to generate timestamps

# Time window configuration
WINDOW_SIZE_SECONDS = 10  # Tokens rotate every 10 seconds
VALIDATION_WINDOW = 1     # Allow tokens from ±1 window (±10 seconds)

def get_time_window(timestamp=None):
    """Calculate the time window for a given timestamp (or current time)."""
    if timestamp is None:
        timestamp = int(time.time())
    # Floor to the nearest 10-second window
    return (timestamp // WINDOW_SIZE_SECONDS) * WINDOW_SIZE_SECONDS

def generate_token(user_id, secret_key):
    # Get current time window instead of exact timestamp
    time_window = get_time_window()
    
    # Create the payload string joining user_id and time window with a colon
    payload = f"{user_id}:{time_window}"
    
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

def verify_token(token, secret_key, validation_window=None):
    """Verify a token and check if it's within the valid time window.
    
    Args:
        token: The token string to verify
        secret_key: The secret key used for signature verification
        validation_window: Number of adjacent windows to allow (default: VALIDATION_WINDOW)
                          If set to 1, allows current window ±1 (total 3 windows)
    
    Returns:
        (bool, dict|string): True with user data if valid, False with error message if invalid
    """
    if validation_window is None:
        validation_window = VALIDATION_WINDOW
    
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
        
    # If the signature is valid, decode the payload to check the time window
    # Add back the base64 padding '=' characters necessary for python's b64decode to work
    padding = '=' * (4 - (len(encoded_payload) % 4))
    decoded_payload_bytes = base64.urlsafe_b64decode(encoded_payload + padding)
    decoded_payload = decoded_payload_bytes.decode('utf-8')
    
    # Split the decoded string payload back into the user_id and the time window
    user_id, token_window = decoded_payload.split(':')
    token_window = int(token_window)
    
    # Get current time window
    current_window = get_time_window()
    
    # Calculate the difference in windows
    window_diff = abs(current_window - token_window) // WINDOW_SIZE_SECONDS
    
    # Check if the token's window is within the allowed validation window
    if window_diff > validation_window:
        return False, f"Token expired (window difference: {window_diff}, allowed: {validation_window})"
        
    # Return success along with the extracted user ID and window info
    return True, {
        "user_id": user_id,
        "token_window": token_window,
        "current_window": current_window,
        "window_diff": window_diff
    }

# Quick test execution
if __name__ == "__main__":
    test_secret = "my_super_secret_key"
    
    print("=== Time-Based Token Rotation Demo ===\n")
    
    # Test 1: Generate and verify a token immediately
    print("--- Test 1: Generate and verify immediately ---")
    my_token = generate_token("user_123", test_secret)
    print(f"Generated Token: {my_token}")
    is_valid, data = verify_token(my_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 2: Verify with different validation windows
    print("--- Test 2: Verify with strict window (0) ---")
    is_valid, data = verify_token(my_token, test_secret, validation_window=0)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 3: Simulate an old token (from previous window)
    print("--- Test 3: Simulate token from previous window ---")
    old_window = get_time_window() - WINDOW_SIZE_SECONDS
    old_payload = f"user_123:{old_window}"
    old_encoded_payload = base64.urlsafe_b64encode(old_payload.encode('utf-8')).rstrip(b'=')
    old_signature = hmac.new(
        key=test_secret.encode('utf-8'),
        msg=old_encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    old_encoded_signature = base64.urlsafe_b64encode(old_signature).rstrip(b'=')
    old_token = f"{old_encoded_payload.decode('utf-8')}.{old_encoded_signature.decode('utf-8')}"
    print(f"Old Token (previous window): {old_token}")
    is_valid, data = verify_token(old_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 4: Token too old (outside validation window)
    print("--- Test 4: Token too old (2 windows back) ---")
    very_old_window = get_time_window() - (WINDOW_SIZE_SECONDS * 2)
    very_old_payload = f"user_123:{very_old_window}"
    very_old_encoded_payload = base64.urlsafe_b64encode(very_old_payload.encode('utf-8')).rstrip(b'=')
    very_old_signature = hmac.new(
        key=test_secret.encode('utf-8'),
        msg=very_old_encoded_payload,
        digestmod=hashlib.sha256
    ).digest()
    very_old_encoded_signature = base64.urlsafe_b64encode(very_old_signature).rstrip(b'=')
    very_old_token = f"{very_old_encoded_payload.decode('utf-8')}.{very_old_encoded_signature.decode('utf-8')}"
    print(f"Very Old Token (2 windows back): {very_old_token}")
    is_valid, data = verify_token(very_old_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    # Test 5: Invalid signature
    print("--- Test 5: Invalid signature (tampered token) ---")
    tampered_token = my_token[:-5] + "xxxxx"
    print(f"Tampered Token: {tampered_token}")
    is_valid, data = verify_token(tampered_token, test_secret)
    print(f"Valid: {is_valid} | Data: {data}\n")
    
    print("=== Demo Complete ===")
