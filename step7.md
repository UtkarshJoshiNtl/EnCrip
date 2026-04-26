# Step 7: Add Minimal API Layer

## Summary

Added a FastAPI-based REST API layer to expose token generation and verification functionality via HTTP endpoints. The API provides a clean interface for external systems to interact with the token system.

## Files Created

- `token_system/api.py` - FastAPI application with `/generate` and `/verify` endpoints
- `requirements.txt` - Python dependencies for FastAPI, Uvicorn, and Pydantic

## Files Modified

- `token_system/__init__.py` - Updated docstring to mention REST API layer

## Code Changes

### New File: token_system/api.py

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict

from .generation import generate_token
from .verification import verify_token
from .config import get_default_secret_key


app = FastAPI(title="Token System API", version="1.0.0")


class GenerateRequest(BaseModel):
    user_id: str
    secret_key: Optional[str] = None
    max_lifetime_seconds: Optional[int] = None


class VerifyRequest(BaseModel):
    token: str
    secret_key: Optional[str] = None
    validation_window: Optional[int] = None
    clock_skew_tolerance: Optional[int] = None
    check_replay: Optional[bool] = None


class GenerateResponse(BaseModel):
    token: str
    user_id: str
    success: bool


class VerifyResponse(BaseModel):
    valid: bool
    data: Optional[Dict] = None
    error: Optional[str] = None


@app.get("/")
def read_root():
    return {
        "message": "Token System API",
        "endpoints": {
            "/generate": "POST - Generate a new token",
            "/verify": "POST - Verify a token"
        }
    }


@app.post("/generate", response_model=GenerateResponse)
def generate_token_endpoint(request: GenerateRequest):
    secret_key = request.secret_key if request.secret_key is not None else get_default_secret_key()
    token = generate_token(
        user_id=request.user_id,
        secret_key=secret_key,
        max_lifetime_seconds=request.max_lifetime_seconds
    )
    return GenerateResponse(token=token, user_id=request.user_id, success=True)


@app.post("/verify", response_model=VerifyResponse)
def verify_token_endpoint(request: VerifyRequest):
    secret_key = request.secret_key if request.secret_key is not None else get_default_secret_key()
    is_valid, result = verify_token(
        token=request.token,
        secret_key=secret_key,
        validation_window=request.validation_window,
        clock_skew_tolerance=request.clock_skew_tolerance,
        check_replay=request.check_replay
    )
    if is_valid:
        return VerifyResponse(valid=True, data=result, error=None)
    else:
        return VerifyResponse(valid=False, data=None, error=result)
```

### New File: requirements.txt

```
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
pydantic>=2.0.0
```

## How API Connects to Token Logic

The API layer acts as a thin wrapper around the existing token system modules:

1. **`/generate` endpoint**:
   - Receives HTTP POST request with JSON body
   - Extracts `user_id`, `secret_key`, and `max_lifetime_seconds`
   - Calls `token_system.generation.generate_token()`
   - Returns JSON response with generated token

2. **`/verify` endpoint**:
   - Receives HTTP POST request with JSON body
   - Extracts `token`, `secret_key`, and optional verification parameters
   - Calls `token_system.verification.verify_token()`
   - Returns JSON response with validity status and data/error

The API does not implement any token logic itself - it purely handles HTTP concerns:
- Request validation via Pydantic models
- JSON serialization/deserialization
- HTTP status codes
- Optional secret key fallback to default

## Example Request/Response

### Generate Token

**Request:**
```bash
curl -X POST "http://localhost:8000/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_123",
    "secret_key": "my_secret_key",
    "max_lifetime_seconds": 300
  }'
```

**Response:**
```json
{
  "token": "dXNlcl8xMjM6MTcxNDM4MjYwMDoxNzE0Mzg4OTAw.ZGVhZGJlZWZjb2Rl",
  "user_id": "user_123",
  "success": true
}
```

### Verify Token (Success)

**Request:**
```bash
curl -X POST "http://localhost:8000/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "dXNlcl8xMjM6MTcxNDM4MjYwMDoxNzE0Mzg4OTAw.ZGVhZGJlZWZjb2Rl",
    "secret_key": "my_secret_key"
  }'
```

**Response:**
```json
{
  "valid": true,
  "data": {
    "user_id": "user_123",
    "token_window": 1714382600,
    "current_window": 1714382600,
    "window_diff": 0,
    "expiration_time": 1714388900,
    "time_until_expiration": 295
  },
  "error": null
}
```

### Verify Token (Failure)

**Request:**
```bash
curl -X POST "http://localhost:8000/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "invalid.token.here",
    "secret_key": "my_secret_key"
  }'
```

**Response:**
```json
{
  "valid": false,
  "data": null,
  "error": "Signature verification failed"
}
```

## Running the API

Install dependencies:
```bash
pip install -r requirements.txt
```

Start the server:
```bash
python -m token_system.api
```

Or using uvicorn directly:
```bash
uvicorn token_system.api:app --host 0.0.0.0 --port 8000
```

Interactive API documentation will be available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Before vs After System Behavior

### Before (Step 6)
- Token system only accessible via Python imports
- Required Python code to generate/verify tokens
- No HTTP interface for external systems
- Testing required writing Python scripts

### After (Step 7)
- Token system accessible via REST API
- Any HTTP client can generate/verify tokens
- Clean JSON request/response format
- Interactive API documentation (Swagger/ReDoc)
- Easy integration with web apps, mobile apps, CLI tools
- Can be deployed as microservice
