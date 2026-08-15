from passlib.hash import pbkdf2_sha256

from database import SessionLocal
from models import User


db = SessionLocal()

try:
    username = "admin01"
    password = "Admin@123"

    existing_admin = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if existing_admin:
        existing_admin.role = "Admin"
        existing_admin.password = pbkdf2_sha256.hash(password)

        db.commit()

        print("Existing account updated as Admin.")

    else:
        admin = User(
            username=username,
            password=pbkdf2_sha256.hash(password),
            role="Admin"
        )

        db.add(admin)
        db.commit()

        print("Admin account created successfully.")

    print("Username: admin01")
    print("Password: Admin@123")

except Exception as error:
    db.rollback()
    print("Admin creation failed:", error)

finally:
    db.close()