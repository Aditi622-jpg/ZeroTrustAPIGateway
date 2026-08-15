import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.hash import pbkdf2_sha256
from sqlalchemy.orm import Session

from audit import log_event
from database import SessionLocal
from models import User


router = APIRouter()
templates = Jinja2Templates(directory="templates")


# JWT configuration
SECRET_KEY = "zero-trust-secret-key-2026"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30


def validate_username(username: str):
    """
    Validate usernames for registration and admin user creation.
    Returns an error message when invalid, otherwise returns None.
    """

    if len(username) < 4:
        return "Username must contain at least 4 characters"

    if len(username) > 30:
        return "Username cannot exceed 30 characters"

    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return (
            "Username can contain only letters, "
            "numbers and underscore"
        )

    return None


def validate_password(password: str):
    """
    Validate password strength.
    Returns an error message when invalid, otherwise returns None.
    """

    if len(password) < 8:
        return "Password must contain at least 8 characters"

    if len(password) > 72:
        return "Password cannot exceed 72 characters"

    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter"

    if not re.search(r"\d", password):
        return "Password must contain at least one number"

    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character"

    return None


def create_access_token(username: str, role: str):
    expiry_time = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE_MINUTES
    )

    token_data = {
        "sub": username,
        "role": role,
        "exp": expiry_time
    }

    token = jwt.encode(
        token_data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token


def verify_access_token(token: str):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")
        role = payload.get("role")

        if username is None:
            return None

        return {
            "username": username,
            "role": role
        }

    except JWTError:
        return None


@router.post("/register")
async def register(
    username: str = Form(...),
    password: str = Form(...)
):
    db: Session = SessionLocal()

    try:
        username = username.strip()
        password = password.strip()

        if not username or not password:
            error_message = quote_plus(
                "Username and password are required"
            )

            return RedirectResponse(
                url=f"/login-page?error={error_message}",
                status_code=303
            )

        username_error = validate_username(username)

        if username_error:
            return RedirectResponse(
                url=(
                    "/login-page?error="
                    f"{quote_plus(username_error)}"
                ),
                status_code=303
            )

        password_error = validate_password(password)

        if password_error:
            return RedirectResponse(
                url=(
                    "/login-page?error="
                    f"{quote_plus(password_error)}"
                ),
                status_code=303
            )

        existing_user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if existing_user:
            error_message = quote_plus(
                "Username already exists"
            )

            return RedirectResponse(
                url=f"/login-page?error={error_message}",
                status_code=303
            )

        hashed_password = pbkdf2_sha256.hash(password)

        new_user = User(
            username=username,
            password=hashed_password,
            role="User"
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        log_event(
            username=username,
            action="User Registration",
            status="Success"
        )

        success_message = quote_plus(
            "Registration successful. Please login."
        )

        return RedirectResponse(
            url=f"/login-page?message={success_message}",
            status_code=303
        )

    except Exception as error:
        db.rollback()

        log_event(
            username=username if username else "Anonymous",
            action="User Registration",
            status="Failed"
        )

        error_message = quote_plus(
            f"Registration failed: {str(error)}"
        )

        return RedirectResponse(
            url=f"/login-page?error={error_message}",
            status_code=303
        )

    finally:
        db.close()


@router.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...)
):
    db: Session = SessionLocal()

    try:
        username = username.strip()

        if not username or not password:
            error_message = quote_plus(
                "Username and password are required"
            )

            return RedirectResponse(
                url=f"/login-page?error={error_message}",
                status_code=303
            )

        user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if user is None:
            log_event(
                username=username,
                action="User Login",
                status="Failed"
            )

            error_message = quote_plus(
                "Invalid username or password"
            )

            return RedirectResponse(
                url=f"/login-page?error={error_message}",
                status_code=303
            )

        password_is_correct = pbkdf2_sha256.verify(
            password,
            user.password
        )

        if not password_is_correct:
            log_event(
                username=username,
                action="User Login",
                status="Failed"
            )

            error_message = quote_plus(
                "Invalid username or password"
            )

            return RedirectResponse(
                url=f"/login-page?error={error_message}",
                status_code=303
            )

        token = create_access_token(
            username=user.username,
            role=user.role
        )

        log_event(
            username=user.username,
            action="User Login",
            status="Success"
        )

        response = RedirectResponse(
            url="/dashboard",
            status_code=303
        )

        response.set_cookie(
            key="access_token",
            value=token,
            httponly=True,
            max_age=TOKEN_EXPIRE_MINUTES * 60,
            samesite="lax"
        )

        return response

    except Exception as error:
        error_message = quote_plus(
            f"Login failed: {str(error)}"
        )

        return RedirectResponse(
            url=f"/login-page?error={error_message}",
            status_code=303
        )

    finally:
        db.close()


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    token = request.cookies.get("access_token")

    if token is None:
        error_message = quote_plus(
            "Please login first"
        )

        return RedirectResponse(
            url=f"/login-page?error={error_message}",
            status_code=303
        )

    user_data = verify_access_token(token)

    if user_data is None:
        error_message = quote_plus(
            "Session expired. Please login again."
        )

        response = RedirectResponse(
            url=f"/login-page?error={error_message}",
            status_code=303
        )

        response.delete_cookie("access_token")
        return response

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "username": user_data["username"],
            "role": user_data["role"]
        }
    )


@router.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("access_token")

    if token is not None:
        user_data = verify_access_token(token)

        if user_data is not None:
            log_event(
                username=user_data["username"],
                action="User Logout",
                status="Success"
            )

    success_message = quote_plus(
        "You have been logged out successfully."
    )

    response = RedirectResponse(
        url=f"/login-page?message={success_message}",
        status_code=303
    )

    response.delete_cookie("access_token")

    return response