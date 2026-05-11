import time
import sys
import os

# Add the token_system to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from token_system import generate_token, verify_token, get_default_secret_key
from token_system.config import ENABLE_REPLAY_PROTECTION

def debug_encrip():
    secret = get_default_secret_key()
    print(f"Replay Protection Enabled: {ENABLE_REPLAY_PROTECTION}")
    
    print("\n--- Testing Expiration ---")
    token = generate_token("user1", secret, max_lifetime_seconds=1)
    print(f"Token generated: {token}")
    time.sleep(1.2)
    is_valid, error = verify_token(token, secret)
    print(f"Valid after 1.2s: {is_valid} | Error: {error}")
    
    print("\n--- Testing Replay ---")
    token2 = generate_token("user2", secret)
    is_valid, error = verify_token(token2, secret)
    print(f"First use: {is_valid}")
    is_valid, error = verify_token(token2, secret)
    print(f"Second use: {is_valid} | Error: {error}")

    print("\n--- Testing Performance ---")
    start = time.time()
    for i in range(100):
        t = generate_token(f"user{i}", secret)
        verify_token(t, secret)
    end = time.time()
    print(f"100 gen+verify took: {end - start:.4f}s ({(100/(end-start)):.2f} ops/sec)")

if __name__ == "__main__":
    debug_encrip()
