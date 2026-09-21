from fastapi import APIRouter
from app.api.v1.endpoints import emails

api_v1_router = APIRouter()
api_v1_router.include_router(emails.router, prefix="/emails", tags=["Emails"])
