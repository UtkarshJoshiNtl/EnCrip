import hmac       # Used to create the cryptographic signature
import hashlib    # Provides the hashing algorithms like SHA256
import base64     # Used to safely encode the bytes into string format
import time       # Used to generate timestamps

def generate_token(user_id, secret_key):
    # Get current timestamp as an integer to prevent infinite validity
    timestamp = int(time.time())
    
    # Create the payload string joining user_id and timestamp with a colon
    payload = f"{user_id}:{timestamp}"
    
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

def verify_token(token, secret_key, max_age_seconds=3600):
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
        
    # If the signature is valid, decode the payload to check the timestamp
    # Add back the base64 padding '=' characters necessary for python's b64decode to work
    padding = '=' * (4 - (len(encoded_payload) % 4))
    decoded_payload_bytes = base64.urlsafe_b64decode(encoded_payload + padding)
    decoded_payload = decoded_payload_bytes.decode('utf-8')
    
    # Split the decoded string payload back into the user_id and the token submission time
    user_id, token_timestamp = decoded_payload.split(':')
    
    # Check if current time minus token creation time is greater than the allowed maximum age
    if int(time.time()) - int(token_timestamp) > max_age_seconds:
        return False, "Token expired"
        
    # Return success along with the extracted user ID
    return True, {"user_id": user_id}

# Quick test execution
if __name__ == "__main__":
    test_secret = "my_super_secret_key"
    print("--- Generating token ---")
    my_token = generate_token("user_123", test_secret)
    print("Resulting Token:", my_token)
    
    print("\n--- Verifying token ---")
    is_valid, data = verify_token(my_token, test_secret)
    print("Is valid:", is_valid, "| Extracted Data:", data)
