from database import SessionLocal
from models import AuditLog


def log_event(username, action, status):

    db = SessionLocal()

    try:

        new_log = AuditLog(
            username=username,
            action=action,
            status=status
        )

        db.add(new_log)
        db.commit()

    finally:

        db.close()