import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

# HTTP Bearer authentication scheme
security_bearer = HTTPBearer(auto_error=False)


def verify_api_auth(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)) -> str:
    """Authentication dependency validating API Bearer token with constant-time comparison."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided_token = credentials.credentials.strip()
    expected_token = settings.API_SECRET_KEY.strip()

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(provided_token, expected_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return provided_token
