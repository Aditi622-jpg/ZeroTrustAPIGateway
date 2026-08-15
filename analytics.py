from database import SessionLocal
from models import APIAnalytics


def log_api_request(
    username: str,
    endpoint: str,
    method: str,
    request_status: str,
    response_code: int
):
    db = SessionLocal()

    try:
        analytics_entry = APIAnalytics(
            username=username,
            endpoint=endpoint,
            method=method,
            status=request_status,
            response_code=response_code
        )

        db.add(analytics_entry)
        db.commit()

    except Exception:
        db.rollback()

    finally:
        db.close()