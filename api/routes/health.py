"""GET /health — Health check endpoint."""

from fastapi import APIRouter

from api.models import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service health status.",
)
async def health_endpoint() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="0.1.0", service="GuardHire")
