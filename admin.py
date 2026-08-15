from database import SessionLocal
from models import User
from passlib.hash import pbkdf2_sha256


db = SessionLocal()

try:
    username = "admin01"
    password = "Admin@123"

    existing_user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if existing_user:
        existing_user.password = pbkdf2_sha256.hash(password)
        existing_user.role = "Admin"

        db.commit()

        print("Existing account updated successfully.")
        print("Username: admin01")
        print("Password: Admin@123")
        print("Role: Admin")

    else:
        admin_user = User(
            username=username,
            password=pbkdf2_sha256.hash(password),
            role="Admin"
        )

        db.add(admin_user)
        db.commit()

        print("Administrator account created successfully.")
        print("Username: admin01")
        print("Password: Admin@123")
        print("Role: Admin")

finally:
    db.close()