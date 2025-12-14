from fastapi import APIRouter

router = APIRouter(prefix="/api",tags=["HealthCheck"])

@router.get("/health")
def healthCheck():
    return {"Status":"Server running Fine"}