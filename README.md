# EnCrip - Stateless HMAC-Based Token System

A minimal, educational implementation of stateless HMAC-based authentication tokens with time-based validity, replay protection, and a REST API layer.

## What the System Does

The EnCrip token system is a **stateless HMAC-based authentication token system** that provides:

1. **Token Generation**: Creates cryptographically signed tokens containing user identity, time window, and expiration
2. **Token Verification**: Validates tokens using HMAC signature verification, time window checks, and replay protection
3. **Time-Based Validity**: Tokens are valid within rotating time windows (10-second intervals) with absolute expiration (5 minutes max)
4. **Security Features**: 
   - HMAC-SHA256 signatures for integrity and authenticity
   - Clock skew tolerance (15 seconds) for client-server time differences
   - Replay attack detection via in-memory token cache
   - Timing-safe signature comparison to prevent timing attacks
5. **API Layer**: REST API endpoints for token generation and verification
6. **Logging**: Structured logging for operational visibility and security monitoring

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### Python API

```python
from token_system import generate_token, verify_token

# Generate a token
token = generate_token("user_123", "my_secret_key")
print(f"Token: {token}")

# Verify a token
is_valid, data = verify_token(token, "my_secret_key")
if is_valid:
    print(f"Valid! User: {data['user_id']}")
else:
    print(f"Invalid: {data}")
```

### REST API

Start the server:
```bash
python -m token_system.api
```

Generate a token:
```bash
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user_123", "secret_key": "my_secret_key"}'
```

Verify a token:
```bash
curl -X POST "http://localhost:8000/verify" \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN", "secret_key": "my_secret_key"}'
```

Interactive API documentation available at http://localhost:8000/docs

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

1. **Calculate time window**: Floor current timestamp to 10-second intervals
2. **Calculate absolute expiration**: Current time + max lifetime (default 300s)
3. **Create payload string**: `user_id:time_window:expiration_time`
4. **Encode payload to base64**: URL-safe encoding without padding
5. **Generate HMAC-SHA256 signature**: Using secret key and encoded payload
6. **Encode signature to base64**: URL-safe encoding without padding
7. **Combine**: `encoded_payload.encoded_signature`

## Verification Flow

1. **Validate token format**: Must contain exactly one dot delimiter
2. **Split token**: Separate payload and signature
3. **Recompute expected signature**: HMAC-SHA256 with secret key
4. **Compare signatures**: Timing-safe comparison to prevent timing attacks
5. **Decode payload**: Base64 decode with padding restoration
6. **Parse components**: Extract user_id, time_window, expiration_time
7. **Check absolute expiration**: Reject if expired (with clock skew tolerance)
8. **Check time window**: Reject if outside validation window (±1 window)
9. **Check future tokens**: Reject if too far in future (clock skew protection)
10. **Check replay attack**: Reject if token already used
11. **Return success**: Extracted user data and metadata

## Key Design Decisions

### 1. Stateless Token Design

**Decision**: Tokens contain all necessary information (user_id, time_window, expiration) and are verified without database lookups.

**Rationale**:
- Eliminates database dependency for verification
- Enables horizontal scaling (any server can verify any token)
- Reduces latency (no network calls to database)
- Simplifies architecture (no session storage)

**Tradeoff**: Cannot revoke tokens before expiration without adding state (blacklist)

### 2. HMAC-SHA256 for Signing

**Decision**: Use HMAC-SHA256 for token signatures.

**Rationale**:
- Industry-standard cryptographic primitive
- 256-bit security level (computationally infeasible to brute force)
- Widely available in all programming languages
- Resistant to length extension attacks
- Faster than asymmetric cryptography (RSA, ECDSA)

**Tradeoff**: Requires shared secret key between token generator and verifier

### 3. Time Window + Absolute Expiration

**Decision**: Combine rotating time windows (10s) with absolute expiration (5min).

**Rationale**:
- **Time window**: Limits replay window, forces token refresh
- **Absolute expiration**: Prevents indefinite validity, handles edge cases
- **Dual approach**: Balances security (short window) with usability (grace period)

**Tradeoff**: More complex than single expiration mechanism

### 4. In-Memory Replay Cache

**Decision**: Use in-memory cache to track used tokens for replay protection.

**Rationale**:
- Simple implementation
- Fast lookups (O(1) with hash map)
- No external dependencies
- Sufficient for single-server deployments

**Tradeoff**: 
- Lost on server restart
- Not distributed across multiple servers
- Memory grows with token volume (mitigated by cleanup)

## Threat Model

### Threat 1: Replay Attack

**Description**: Attacker captures a valid token and reuses it to gain unauthorized access.

**Current Protection**:
- In-memory cache of used token hashes
- Tokens removed from cache after 300 seconds
- Configurable via `ENABLE_REPLAY_PROTECTION`

**Effectiveness**:
- **Strong**: Prevents replay within token lifetime
- **Limitation**: In-memory cache lost on server restart
- **Limitation**: Doesn't work across multiple server instances

**Where Protection Exists in Code**:
- Configuration: `token_system/config.py:20-21`
- Detection logic: `token_system/verification.py:50-68`
- Cleanup logic: `token_system/verification.py:30-48`

### Threat 2: Token Leakage

**Description**: Token is exposed through logs, error messages, or insecure storage.

**Current Protection**:
- Tokens are NOT logged in full (only user_id and metadata logged)
- Error messages do not include full token
- Timing-safe signature comparison prevents timing attacks

**Effectiveness**:
- **Partial**: System doesn't log tokens, but caller must handle securely
- **Limitation**: Caller responsible for HTTPS, secure storage

**Where Protection Exists in Code**:
- Logging: `token_system/generation.py:74-79`
- Logging: `token_system/verification.py:198-202`
- Timing-safe comparison: `token_system/verification.py:121`

### Threat 3: Brute Force Attack

**Description**: Attacker attempts to guess valid tokens or secret key through systematic trial.

**Current Protection**:
- HMAC-SHA256 provides 256-bit security (2^256 possible signatures)
- Token entropy: Time window + user_id + expiration create large search space

**Effectiveness**:
- **Strong against signature forgery**: HMAC-SHA256 is cryptographically secure
- **Strong against secret key brute force**: 256-bit key space is infeasible
- **Weak against token guessing**: If user_id is predictable and time window known
- **No protection against online attacks**: No rate limiting or account lockout

**Known Limitations**:
1. No rate limiting: Attacker could make unlimited verification attempts
2. No account lockout: Failed attempts don't trigger lockout
3. Predictable user_ids: If user_ids are sequential, easier to guess

## Security Considerations

### Secret Key Management
- **Current**: Default key in code (`get_default_secret_key()`)
- **Risk**: Hardcoded secrets are vulnerable if code is exposed
- **Recommendation**: Load from environment variables or secret management system

### Clock Skew
- **Current**: 15-second tolerance
- **Risk**: Large clock skew could allow token reuse
- **Protection**: Rejects tokens too far in future

### Token Lifetime
- **Current**: 5 minutes maximum
- **Risk**: Longer lifetime increases exposure window
- **Tradeoff**: Shorter lifetime = more frequent token generation

## Known Limitations

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

## Tradeoffs: Stateless vs Stateful

### Stateless Design (Current Implementation)

**Advantages**:
- **Scalability**: Any server can verify any token without shared state
- **Performance**: No database lookups during verification
- **Simplicity**: No session storage infrastructure needed
- **Reliability**: No single point of failure (database)
- **Cost**: Reduced database load and infrastructure

**Disadvantages**:
- **No revocation**: Cannot invalidate tokens before expiration
- **Limited metadata**: Token size limits embedded information
- **Replay protection**: Requires additional state (cache)
- **Audit trail**: Harder to track token usage without logging

### Stateful Design (Alternative)

**Advantages**:
- **Revocation**: Can invalidate tokens immediately
- **Rich metadata**: Can store additional data server-side
- **Audit**: Complete token usage history
- **Flexible**: Can change validation logic without reissuing tokens

**Disadvantages**:
- **Database dependency**: Requires database for verification
- **Latency**: Network calls to database during verification
- **Scalability**: Database becomes bottleneck at scale
- **Complexity**: Session management infrastructure
- **Cost**: Higher infrastructure costs for database

## Real-World Parallels

### Feature: HMAC-Signed Tokens
**Real-World Parallel**: **JWT (JSON Web Tokens)**
- Similarities: Cryptographic signatures, stateless, expiration claims
- Differences: JWT uses JSON format, standardized claims, multiple algorithms

### Feature: Time-Based Validity
**Real-World Parallel**: **TOTP (Time-based One-Time Passwords)**
- Similarities: Time windows, replay protection, clock skew handling
- Differences: TOTP uses 30-second windows, for 2FA, per-user secrets

### Feature: Replay Protection
**Real-World Parallel**: **OAuth 2.0 Nonce/State Parameters**
- Similarities: Tracking used requests, caching mechanism
- Differences: OAuth uses short-lived nonces for authorization requests

### Feature: Clock Skew Tolerance
**Real-World Parallel**: **Kerberos**
- Similarities: Clock difference handling, future token rejection
- Differences: Kerberos uses 5-minute skew, requires NTP synchronization

## Real-World Use Cases

This token system is suitable for:

1. **API Authentication**: Similar to how Stripe or Twilio use API keys with HMAC signatures
2. **Microservice Communication**: Service-to-service authentication without shared database
3. **Temporary Access Tokens**: Short-lived tokens for file downloads, password resets
4. **Webhook Verification**: Verifying webhook signatures (like GitHub webhooks)
5. **Stateless Sessions**: Alternative to JWT for simple session management

Not suitable for:

1. **Long-lived sessions**: Better to use stateful sessions with refresh tokens
2. **Complex user management**: Need full identity provider (Auth0, Firebase)
3. **Token revocation requirements**: Need stateful blacklist or JWT with revocation
4. **High-security environments**: Need additional factors (MFA, device binding)

## Design Philosophy

The system follows these principles:

1. **Minimalism**: Only essential features, no over-engineering
2. **Correctness**: Cryptographic best practices (timing-safe comparison, proper key handling)
3. **Clarity**: Simple, readable code with clear separation of concerns
4. **Educational**: Demonstrates fundamental token authentication concepts
5. **Extensibility**: Modular design allows adding features (Redis cache, rate limiting, etc.)

## Project Structure

```
EnCrip/
├── token_system/
│   ├── __init__.py          # Package initialization and public API
│   ├── config.py            # Configuration constants
│   ├── generation.py        # Token generation logic
│   ├── verification.py      # Token verification and replay protection
│   ├── api.py               # FastAPI REST API layer
│   └── logger.py            # Logging configuration
├── token_sys.py             # Backward compatibility wrapper
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## Conclusion

The EnCrip token system is a **minimal, educational implementation of stateless HMAC-based authentication**. It demonstrates core concepts used in production systems like JWT, TOTP, and API signature schemes while maintaining simplicity and clarity.

The design choices prioritize:
- **Understanding** over production features
- **Correctness** over completeness
- **Simplicity** over flexibility

For production use, this system would need enhancements like:
- Persistent replay cache (Redis)
- Rate limiting
- Secret key management (environment variables, vault)
- HTTPS enforcement
- Token revocation mechanism
- Distributed tracing
- Metrics and monitoring
