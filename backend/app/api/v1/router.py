from fastapi import APIRouter
from app.api.v1.email_analysis import router as email_analysis_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.auth import router as auth_router

api_v1_router = APIRouter()
api_v1_router.include_router(auth_router)
api_v1_router.include_router(email_analysis_router)
api_v1_router.include_router(investigations_router)
