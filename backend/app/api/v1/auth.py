from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.auth import TokenSchema, UserLoginRequest, UserProfileSchema
from app.core.security import create_access_token
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenSchema, summary="Analyst Station Login")
def login(login_req: UserLoginRequest):
    """Authenticate cybersecurity analyst and issue JWT access token."""
    # Development validation
    if login_req.email and len(login_req.password) >= 4:
        token = create_access_token({
            "sub": login_req.email,
            "name": "Dhruv Sharma",
            "role": "Senior Digital Forensics Lead",
            "org": "Cyber Defense & Threat Intelligence Division",
        })
        return TokenSchema(
            access_token=token,
            token_type="bearer",
            expires_in=60 * 60 * 24,
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid investigator credentials",
    )

@router.get("/me", response_model=UserProfileSchema, summary="Get Current Analyst Profile")
def get_me(current_user: UserProfileSchema = Depends(get_current_user)):
    """Return currently authenticated analyst profile details."""
    return current_user
