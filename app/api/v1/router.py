from fastapi import APIRouter
from app.api.v1.endpoints import (
    analysis,
    cases,
    emails,
    fono,
    quarantine,
    security,
    spam,
)

api_v1_router = APIRouter()

api_v1_router.include_router(emails.router, prefix="/emails", tags=["Emails"])
api_v1_router.include_router(spam.router, prefix="/spam", tags=["Spam"])
api_v1_router.include_router(quarantine.router, prefix="/quarantine", tags=["Quarantine"])
api_v1_router.include_router(cases.router, prefix="/cases", tags=["Cases"])
api_v1_router.include_router(security.router, prefix="/security", tags=["Security"])
api_v1_router.include_router(fono.router, prefix="/fono", tags=["Fono"])
api_v1_router.include_router(analysis.router, prefix="/analysis", tags=["Analysis"])
