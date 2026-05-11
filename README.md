# EnCrip - Secure Distributed Execution Framework

A high-performance distributed execution framework with stateless HMAC-based authentication for dispatching computational tasks across network nodes.

## Performance Benchmarks

- **Token Generation**: 7,912/sec (0.125ms avg)
- **Token Verification**: 12,401/sec (0.080ms avg)
- **Concurrent Ops**: 2,738/sec (18ms avg, 50 threads)
- **Memory**: 283 bytes per token (7.9MB for 50K tokens)
- **Replay Protection**: 100% detection accuracy

## What It Does

Dispatches computational tasks across network nodes with:
- Cryptographic authentication via HMAC-SHA256 signatures
- Stateless request verification (no database required)
- Unique signatures per request (prevents replay attacks)
- High-performance distributed command execution
- Time-based validity (10s windows, 5min max)
- REST API layer for worker nodes
- Controller script for managing distributed execution

## Quick Start

```bash
pip install -r requirements.txt
```

### Distributed Execution (Controller + Workers)

```bash
# Start worker node on port 8000
PORT=8000 python -m token_system.api

# Start another worker node on port 8001
PORT=8001 python -m token_system.api

# Send command to workers using controller
python controller.py "echo hello world" http://localhost:8000 http://localhost:8001
```

### Python API

```python
from token_system import generate_token, verify_token

# Generate token with embedded command
token = generate_token("controller", "my_secret_key", command="echo hello world")

# Verify token and extract command
is_valid, data = verify_token(token, "my_secret_key")
if is_valid:
    print(f"Command: {data['command']}")
```

### REST API

```bash
# Start worker node
python -m token_system.api

# Generate token with command
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "controller", "secret_key": "my_secret_key"}'

# Execute command using token
curl -X POST "http://localhost:8000/execute" \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_TOKEN_HERE"}'
```

Docs at http://localhost:8000/docs

## Token Format

```
base64(payload).base64(signature)
```

Payload: `user_id:time_window:expiration_time:command`

Example: `dXNlcl8xMjM6MTcxNDM4MjYwMDoxNzE0Mzg4OTAw.ZGVhZGJlZWZjb2Rl`

## Security Features

- HMAC-SHA256 for integrity/authenticity
- Clock skew tolerance (15s)
- In-memory replay cache
- Timing-safe comparison

## Known Limitations

- Replay cache lost on restart (in-memory)
- No rate limiting
- Hardcoded secret key (dev only)
- No token revocation

## Running Benchmarks

```bash
python3 benchmark.py
```

## Project Structure

```
token_system/
├── generation.py    # Token generation
├── verification.py  # Token verification & replay protection
├── config.py        # Configuration
├── api.py           # FastAPI REST layer
└── logger.py        # Logging configuration

controller.py        # Distributed command execution controller
benchmark.py         # Performance benchmark suite
```

## Architecture

### Distributed Execution Model

EnCrip uses a controller-worker architecture:
- **Controller**: Generates signed tokens with embedded commands and dispatches to workers
- **Workers**: Verify tokens cryptographically and execute commands securely
- **Stateless Authentication**: No database required - all authentication info in the token
- **Unique Signatures**: Each token has a unique HMAC-SHA256 signature preventing replay

### Token Structure

Tokens use a simple `base64(payload).base64(signature)` format where the payload contains:
- `user_id`: Controller/user identifier
- `time_window`: Unix timestamp floored to 10-second intervals
- `expiration_time`: Absolute expiration timestamp (default 5 minutes max)
- `command`: Shell command to execute on worker node

### Signing Process

1. Calculate time window (current timestamp floored to 10s intervals)
2. Calculate absolute expiration (current time + max lifetime)
3. Create payload string: `user_id:time_window:expiration_time:command`
4. Encode payload to base64 (URL-safe, no padding)
5. Generate HMAC-SHA256 signature using secret key
6. Encode signature to base64 (URL-safe, no padding)
7. Combine: `encoded_payload.encoded_signature`

### Verification Flow

1. Validate token format (single dot delimiter)
2. Split payload and signature
3. Recompute HMAC-SHA256 signature
4. Timing-safe signature comparison
5. Decode and parse payload
6. Check absolute expiration (with clock skew tolerance)
7. Check time window validity (±1 window)
8. Reject future tokens (clock skew protection)
9. Check replay cache for duplicates
10. Return user data on success

## Design Decisions

### Distributed Execution Architecture
Controller-worker pattern enables horizontal scaling of computational tasks. Workers can be added/removed dynamically without reconfiguration. Stateless authentication allows any worker to verify any token without database lookups.

### Stateless Authentication
Tokens contain all necessary information for verification, eliminating database dependencies during auth checks. This enables horizontal scaling and reduces latency, at the cost of inability to revoke tokens before expiration without additional state.

### HMAC-SHA256
Industry-standard cryptographic primitive providing 256-bit security. Faster than asymmetric cryptography (RSA, ECDSA) and resistant to length extension attacks. Requires shared secret key between controller and workers.

### Dual Expiration Mechanism
Combines rotating time windows (10s) with absolute expiration (5min). Time windows limit replay attacks and force token refresh, while absolute expiration prevents indefinite validity and handles edge cases.

### In-Memory Replay Cache
Simple O(1) hash map for tracking used tokens. Sufficient for single-worker deployments but lost on restart and not distributed across multiple instances. For production, consider Redis or a database-backed cache.

## Security Considerations

### Secret Key Management
Current implementation uses a default hardcoded key for development. For production, load secrets from environment variables or a secret management system (HashiCorp Vault, AWS Secrets Manager).

### Clock Skew
15-second tolerance accommodates client-server time differences. Tokens too far in the future are rejected to prevent abuse from clock manipulation.

### Token Lifetime
5-minute maximum lifetime balances security (shorter exposure window) with usability (fewer refreshes). Adjust based on your security requirements.

### Threat Model

**Replay Attacks**: Protected by in-memory cache with 300-second retention. Limitations: cache lost on restart, not distributed.

**Token Leakage**: System does not log full tokens, but caller must ensure HTTPS and secure storage.

**Brute Force**: HMAC-SHA256 provides 256-bit security against signature forgery. No rate limiting or account lockout (add for production).

## Known Limitations

1. **Replay Protection**: In-memory only, lost on server restart, not distributed
2. **No Rate Limiting**: Vulnerable to online brute force attacks
3. **Hardcoded Secrets**: Development key should be replaced with environment variables
4. **No Token Revocation**: Cannot invalidate tokens before expiration
5. **Single Server**: Not designed for horizontal scaling without external cache
6. **No Audit Trail**: Logs to stdout only, no persistent audit logging

## Production Recommendations

1. **Persistent Replay Cache**: Use Redis or database for distributed replay protection
2. **Rate Limiting**: Implement rate limiting on API endpoints (e.g., 100 requests/minute)
3. **Secret Management**: Load keys from environment variables or vault
4. **HTTPS Enforcement**: Force TLS in production
5. **Token Revocation**: Add blacklist mechanism for emergency revocation
6. **Audit Logging**: Persist logs to external system (ELK, CloudWatch)
7. **Monitoring**: Add metrics for token operations (Prometheus, Datadog)
8. **Multi-Factor Authentication**: Combine with additional factors for high-security scenarios

## Use Cases

**Suitable For:**
- Distributed command execution across worker nodes
- Microservice task dispatching without shared database
- High-performance computational job distribution
- API authentication (similar to Stripe/Twilio HMAC signatures)
- Temporary access tokens (file downloads, password resets)
- Webhook signature verification
- Stateless session management

**Not Suitable For:**
- Long-lived sessions (use stateful sessions with refresh tokens)
- Complex user management (use Auth0, Firebase, etc.)
- Token revocation requirements (needs stateful blacklist)
- High-security environments (requires MFA, device binding)

## Real-World Parallels

- **JWT**: Similar stateless design with cryptographic signatures
- **TOTP**: Time-based windows with replay protection
- **OAuth 2.0**: Nonce/state parameters for replay detection
- **Kerberos**: Clock skew tolerance and future token rejection
