# Step 9: System Design and Threat Model

## Summary

Created comprehensive system documentation explaining token structure, signing process, verification flow, and threat model covering replay attacks, token leakage, and brute force attacks.

## Files Created

- `step9.md` - This document (system design and threat model)

## Files Modified

- None (documentation only)

## Token Structure

### Format
```
base64(payload).base64(signature)
```

### Payload Structure
```
user_id:time_window:expiration_time
```

### Example
```
dXNlcl8xMjM6MTcxNDM4MjYwMDoxNzE0Mzg4OTAw.ZGVhZGJlZWZjb2Rl
```

Breaking down the example:
- **Payload (base64 decoded)**: `user_123:1714382600:1714388900`
  - `user_123`: User identifier
  - `1714382600`: Time window (Unix timestamp, floored to 10-second intervals)
  - `1714388900`: Absolute expiration time (Unix timestamp)
- **Signature (base64 decoded)**: 32-byte HMAC-SHA256 signature

### Design Rationale
- **Base64 encoding**: URL-safe, avoids special characters, easy to transport
- **Dot delimiter**: Simple, unambiguous separator between payload and signature
- **Time window**: Reduces token validity period, limits replay window
- **Absolute expiration**: Prevents indefinite validity even with window rotation
- **HMAC signature**: Cryptographic proof of authenticity and integrity

## Signing Process

### Step-by-Step Flow

1. **Calculate time window**
   ```python
   time_window = (current_timestamp // 10) * 10
   ```
   Location: `token_system/generation.py:89`

2. **Calculate absolute expiration**
   ```python
   expiration_time = current_timestamp + max_lifetime_seconds
   ```
   Location: `token_system/generation.py:94`

3. **Create payload string**
   ```python
   payload = f"{user_id}:{time_window}:{expiration_time}"
   ```
   Location: `token_system/generation.py:97`

4. **Encode payload to base64**
   ```python
   encoded_payload = base64.urlsafe_b64encode(payload.encode('utf-8')).rstrip(b'=')
   ```
   Location: `token_system/generation.py:100`

5. **Generate HMAC-SHA256 signature**
   ```python
   signature = hmac.new(
       key=secret_key.encode('utf-8'),
       msg=encoded_payload,
       digestmod=hashlib.sha256
   ).digest()
   ```
   Location: `token_system/generation.py:105-109`

6. **Encode signature to base64**
   ```python
   encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')
   ```
   Location: `token_system/generation.py:112`

7. **Combine payload and signature**
   ```python
   token = f"{encoded_payload.decode('utf-8')}.{encoded_signature.decode('utf-8')}"
   ```
   Location: `token_system/generation.py:115`

### Security Properties
- **Secret key**: Never exposed, used only for HMAC computation
- **HMAC-SHA256**: Cryptographically secure, collision-resistant
- **Signature covers entire payload**: Any modification invalidates signature
- **Timing attack resistant**: Uses `hmac.compare_digest()` for verification

## Verification Flow

### Step-by-Step Flow

1. **Validate token format**
   ```python
   if token.count('.') != 1:
       return False, "Invalid token format"
   ```
   Location: `token_system/verification.py:142-143`

2. **Split token into payload and signature**
   ```python
   encoded_payload, encoded_signature = token.split('.')
   ```
   Location: `token_system/verification.py:146`

3. **Recompute expected signature**
   ```python
   expected_signature = hmac.new(
       key=secret_key.encode('utf-8'),
       msg=encoded_payload.encode('utf-8'),
       digestmod=hashlib.sha256
   ).digest()
   ```
   Location: `token_system/verification.py:149-153`

4. **Compare signatures (timing-safe)**
   ```python
   if not hmac.compare_digest(encoded_signature, expected_encoded_signature):
       return False, "Signature verification failed"
   ```
   Location: `token_system/verification.py:121-123

5. **Decode payload**
   ```python
   padding = '=' * (4 - (len(encoded_payload) % 4))
   decoded_payload = base64.urlsafe_b64decode(encoded_payload + padding)
   ```
   Location: `token_system/verification.py:164-166`

6. **Parse payload components**
   ```python
   user_id, token_window, expiration_time = decoded_payload.split(':')
   ```
   Location: `token_system/verification.py:170-172

7. **Check absolute expiration**
   ```python
   if current_time > adjusted_expiration:
       return False, "Token expired"
   ```
   Location: `token_system/verification.py:150-155

8. **Check time window validity**
   ```python
   if window_diff > validation_window:
       return False, "Token window expired"
   ```
   Location: `token_system/verification.py:164-169

9. **Check for future tokens (clock skew)**
   ```python
   if token_window > current_window + (clock_skew_tolerance // WINDOW_SIZE_SECONDS):
       return False, "Token from future"
   ```
   Location: `token_system/verification.py:172-177

10. **Check for replay attack**
    ```python
    if check_replay and _is_token_replayed(token):
        return False, "Token already used"
    ```
    Location: `token_system/verification.py:180-184

11. **Return success with extracted data**
    ```python
    return True, {"user_id": user_id, "token_window": token_window, ...}
    ```
    Location: `token_system/verification.py:204

## Threat Model

### Threat 1: Replay Attack

**Description**: Attacker captures a valid token and reuses it to gain unauthorized access.

**Attack Scenario**:
1. Attacker intercepts a valid token from network traffic
2. Attacker replays the token before it expires
3. System accepts the token as valid

**Current Protection**:
- **Location**: `token_system/verification.py:50-68` (`_is_token_replayed()`)
- **Mechanism**: In-memory cache of used token hashes
- **Implementation**:
  ```python
  token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
  if token_hash in _used_tokens:
      return True  # Replay detected
  _used_tokens[token_hash] = int(time.time())
  ```
- **Cleanup**: Tokens removed from cache after `MAX_TOKEN_LIFETIME_SECONDS` (300s)
- **Configurable**: Can be disabled via `ENABLE_REPLAY_PROTECTION = False`

**Effectiveness**:
- **Strong**: Prevents replay within token lifetime
- **Limitation**: In-memory cache lost on server restart
- **Limitation**: Doesn't work across multiple server instances (no distributed cache)
- **Limitation**: Attacker could replay token across different servers if cache not shared

**Where Protection Exists in Code**:
- Configuration: `token_system/config.py:20-21`
- Detection logic: `token_system/verification.py:50-68`
- Cleanup logic: `token_system/verification.py:30-48`
- Verification call: `token_system/verification.py:180-184`

**Known Limitations**:
1. **State loss on restart**: Cache is in-memory, server restart clears it
2. **No persistence**: Tokens not stored in database
3. **No distribution**: Multi-server deployments need shared cache (Redis, etc.)
4. **Memory growth**: Under heavy load, cache could grow large (mitigated by periodic cleanup)

### Threat 2: Token Leakage

**Description**: Token is exposed through logs, error messages, or insecure storage.

**Attack Scenarios**:
1. Token logged in plaintext
2. Token included in error messages
3. Token stored in browser localStorage
4. Token transmitted over HTTP instead of HTTPS

**Current Protection**:
- **Logging**: Tokens are NOT logged in full (only user_id and metadata logged)
  - Location: `token_system/generation.py:74-79` (logs user_id, not token)
  - Location: `token_system/verification.py:198-202` (logs user_id, not token)
- **Error messages**: Do not include full token
  - Location: `token_system/verification.py:123, 155, 169, 177, 184`
- **Signature verification**: Timing-safe comparison prevents timing attacks
  - Location: `token_system/verification.py:121`

**Effectiveness**:
- **Partial**: System doesn't log tokens, but caller must handle securely
- **Limitation**: API layer could log tokens if not configured properly
- **Limitation**: Caller responsible for HTTPS, secure storage

**Where Protection Exists in Code**:
- Logging: `token_system/generation.py:74-79`
- Logging: `token_system/verification.py:198-202`
- Timing-safe comparison: `token_system/verification.py:121`

**Known Limitations**:
1. **Caller responsibility**: System doesn't control how tokens are transmitted/stored
2. **No token masking**: If caller logs token, system can't prevent it
3. **No HTTPS enforcement**: API layer doesn't enforce HTTPS
4. **No token revocation**: Once leaked, token remains valid until expiration

### Threat 3: Brute Force Attack

**Description**: Attacker attempts to guess valid tokens or secret key through systematic trial.

**Attack Scenarios**:
1. **Token guessing**: Attacker generates random tokens and tries to verify them
2. **Secret key brute force**: Attacker tries different secret keys to sign tokens
3. **Signature forgery**: Attacker attempts to forge valid signatures

**Current Protection**:
- **Cryptographic strength**: HMAC-SHA256 provides 256-bit security
  - Location: `token_system/generation.py:105-109`
  - Space: 2^256 possible signatures (computationally infeasible)
- **Token entropy**: Time window + user_id + expiration create large search space
  - Time window: Changes every 10 seconds
  - User ID: Arbitrary string (attacker must know target user)
  - Expiration: Unix timestamp (32 bits)
- **No rate limiting**: System does not implement rate limiting (limitation)
- **No account lockout**: System does not lock accounts after failures (limitation)

**Effectiveness**:
- **Strong against signature forgery**: HMAC-SHA256 is cryptographically secure
- **Strong against secret key brute force**: 256-bit key space is infeasible
- **Weak against token guessing**: If user_id is predictable and time window known, attacker could try combinations
- **No protection against online attacks**: No rate limiting or account lockout

**Where Protection Exists in Code**:
- HMAC computation: `token_system/generation.py:105-109`
- Signature verification: `token_system/verification.py:149-153`
- Timing-safe comparison: `token_system/verification.py:121`

**Known Limitations**:
1. **No rate limiting**: Attacker could make unlimited verification attempts
2. **No account lockout**: Failed attempts don't trigger lockout
3. **Predictable user_ids**: If user_ids are sequential, easier to guess
4. **Time window known**: Attacker knows time window (public information)
5. **No CAPTCHA**: No protection against automated attacks

**Estimated Security**:
- **Secret key space**: 2^256 (if secret key is random 32 bytes)
- **Signature space**: 2^256 (HMAC-SHA256 output)
- **Token space**: Depends on user_id entropy + time window + expiration
- **Brute force time**: With 1 billion attempts/second, would take ~10^67 years to crack HMAC-SHA256

## Additional Security Considerations

### Secret Key Management
- **Current**: Default key in code (`get_default_secret_key()`)
- **Risk**: Hardcoded secrets are vulnerable if code is exposed
- **Recommendation**: Load from environment variables or secret management system
- **Location**: `token_system/config.py:18-20`

### Clock Skew
- **Current**: 15-second tolerance
- **Risk**: Large clock skew could allow token reuse
- **Protection**: Rejects tokens too far in future
- **Location**: `token_system/verification.py:172-177`

### Token Lifetime
- **Current**: 5 minutes maximum
- **Risk**: Longer lifetime increases exposure window
- **Tradeoff**: Shorter lifetime = more frequent token generation
- **Location**: `token_system/config.py:12-13`

### Time Window Size
- **Current**: 10 seconds
- **Risk**: Smaller windows = more sensitive to clock skew
- **Tradeoff**: Larger windows = larger replay window
- **Location**: `token_system/config.py:8`

## Known Limitations Summary

1. **Replay protection**: In-memory only, lost on restart, not distributed
2. **Token leakage**: Caller responsibility for secure transmission/storage
3. **Brute force**: No rate limiting, no account lockout
4. **Secret key**: Hardcoded in development code
5. **No token revocation**: Cannot invalidate tokens before expiration
6. **No audit logging**: Logs to stdout only, no persistent audit trail
7. **Single server**: Not designed for horizontal scaling
8. **No multi-factor**: Token alone is sufficient for authentication

## Recommended Improvements

1. **Persistent replay cache**: Use Redis or database for distributed replay protection
2. **Rate limiting**: Add rate limiting to API endpoints
3. **Secret key management**: Load from environment variables or vault
4. **Token revocation**: Add token blacklist for emergency revocation
5. **Audit logging**: Persist logs to external system
6. **HTTPS enforcement**: Force HTTPS in production
7. **Monitoring**: Add metrics for token operations
8. **Multi-factor**: Combine with additional authentication factors
