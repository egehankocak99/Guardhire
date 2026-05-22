from fastapi import APIRouter

from api.models import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
)
async def health_endpoint() -> HealthResponse:
    return HealthResponse(status="healthy", version="0.1.0", service="GuardHire")
