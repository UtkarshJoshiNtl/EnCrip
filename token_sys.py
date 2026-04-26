# DEPRECATED: This file is kept for backward compatibility.
# New code should use the modular token_system package.
# from token_system import generate_token, verify_token, get_time_window

import time
import base64
import hmac
import hashlib

# Import from new modular structure
from token_system import generate_token, verify_token, get_time_window

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
    
    # Test 8: Replay attack protection
    print("--- Test 8: Replay attack protection ---")
    replay_token = generate_token("user_456", test_secret)
    print(f"Generated Token: {replay_token}")
    is_valid, data = verify_token(replay_token, test_secret)
    print(f"First use - Valid: {is_valid} | Data: {data}")
    is_valid, data = verify_token(replay_token, test_secret)
    print(f"Second use (replay) - Valid: {is_valid} | Data: {data}\n")
    
    # Test 9: Replay protection disabled
    print("--- Test 9: Replay protection disabled ---")
    replay_token2 = generate_token("user_789", test_secret)
    print(f"Generated Token: {replay_token2}")
    is_valid, data = verify_token(replay_token2, test_secret, check_replay=False)
    print(f"First use (replay disabled) - Valid: {is_valid} | Data: {data}")
    is_valid, data = verify_token(replay_token2, test_secret, check_replay=False)
    print(f"Second use (replay disabled) - Valid: {is_valid} | Data: {data}\n")
    
    print("=== Demo Complete ===")
