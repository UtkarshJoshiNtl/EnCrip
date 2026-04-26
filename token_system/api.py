"""FastAPI layer for token system.

Provides REST endpoints for token generation and verification.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Union

from .generation import generate_token
from .verification import verify_token
from .config import get_default_secret_key


app = FastAPI(title="Token System API", version="1.0.0")


class GenerateRequest(BaseModel):
    """Request model for token generation."""
    user_id: str
    secret_key: Optional[str] = None
    max_lifetime_seconds: Optional[int] = None


class VerifyRequest(BaseModel):
    """Request model for token verification."""
    token: str
    secret_key: Optional[str] = None
    validation_window: Optional[int] = None
    clock_skew_tolerance: Optional[int] = None
    check_replay: Optional[bool] = None


class GenerateResponse(BaseModel):
    """Response model for token generation."""
    token: str
    user_id: str
    success: bool


class VerifyResponse(BaseModel):
    """Response model for token verification."""
    valid: bool
    data: Optional[Dict] = None
    error: Optional[str] = None


@app.get("/")
def read_root():
    """Root endpoint with API information."""
    return {
        "message": "Token System API",
        "endpoints": {
            "/generate": "POST - Generate a new token",
            "/verify": "POST - Verify a token"
        }
    }


@app.post("/generate", response_model=GenerateResponse)
def generate_token_endpoint(request: GenerateRequest):
    """Generate a new token for a user.
    
    Args:
        request: GenerateRequest with user_id, optional secret_key, and max_lifetime_seconds
    
    Returns:
        GenerateResponse with the generated token and user_id
    """
    # Use provided secret key or default
    secret_key = request.secret_key if request.secret_key is not None else get_default_secret_key()
    
    # Generate token
    token = generate_token(
        user_id=request.user_id,
        secret_key=secret_key,
        max_lifetime_seconds=request.max_lifetime_seconds
    )
    
    return GenerateResponse(
        token=token,
        user_id=request.user_id,
        success=True
    )


@app.post("/verify", response_model=VerifyResponse)
def verify_token_endpoint(request: VerifyRequest):
    """Verify a token.
    
    Args:
        request: VerifyRequest with token, optional secret_key, validation_window, 
                 clock_skew_tolerance, and check_replay
    
    Returns:
        VerifyResponse with validity status and data or error message
    """
    # Use provided secret key or default
    secret_key = request.secret_key if request.secret_key is not None else get_default_secret_key()
    
    # Verify token
    is_valid, result = verify_token(
        token=request.token,
        secret_key=secret_key,
        validation_window=request.validation_window,
        clock_skew_tolerance=request.clock_skew_tolerance,
        check_replay=request.check_replay
    )
    
    if is_valid:
        return VerifyResponse(
            valid=True,
            data=result,
            error=None
        )
    else:
        return VerifyResponse(
            valid=False,
            data=None,
            error=result
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
