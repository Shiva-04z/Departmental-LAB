from fastapi import APIrouter

router = APIrouter(prefix="/api",tags=["HealthCheck"])

@router.get("/health")
def healthCheck():
    return {"Status":"Server running Fine"}