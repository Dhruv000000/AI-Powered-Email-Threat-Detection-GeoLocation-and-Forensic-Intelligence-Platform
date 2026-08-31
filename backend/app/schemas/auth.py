from typing import Optional
from pydantic import BaseModel, EmailStr

class TokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenPayloadSchema(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    org: Optional[str] = None

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserProfileSchema(BaseModel):
    id: str
    name: str
    email: str
    role: str
    organization: str
