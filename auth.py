import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from jose import JWTError, jwt
from passlib.hash import pbkdf2_sha256
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)
from sqlalchemy.orm import Session

from audit import log_event
from database import SessionLocal
from models import User, OTPVerification
from email_service import send_otp_email


# -------------------------------------------------
# ROUTER CONFIGURATION
# -------------------------------------------------

router = APIRouter()
auth_router = router

templates = Jinja2Templates(directory="templates")


# -------------------------------------------------
# JWT CONFIGURATION
# -------------------------------------------------

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "zero-trust-secret-key-2026"
)

ALGORITHM = "HS256"

TOKEN_EXPIRE_MINUTES = 30

OTP_EXPIRE_MINUTES = 5
OTP_MAX_ATTEMPTS = 3
OTP_RESEND_SECONDS = 60

otp_serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="otp-login"
)


# -------------------------------------------------
# VALIDATION
# -------------------------------------------------

def validate_username(username: str):

    if len(username) < 4:
        return "Username must contain at least 4 characters"

    if len(username) > 30:
        return "Username cannot exceed 30 characters"

    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return "Username can contain only letters, numbers and underscore"

    return None


def validate_password(password: str):

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


def validate_email(email: str):

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return "Please enter a valid email address"

    return None


# -------------------------------------------------
# JWT FUNCTIONS
# -------------------------------------------------

def create_access_token(username: str, role: str):

    expiry_time = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE_MINUTES
    )

    token_data = {
        "sub": username,
        "role": role,
        "exp": expiry_time
    }

    return jwt.encode(
        token_data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


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


# -------------------------------------------------
# OTP GENERATION AND EMAIL DELIVERY
# -------------------------------------------------

async def generate_and_send_otp(db, user):

    # Invalidate previous unused OTPs

    db.query(OTPVerification).filter(
        OTPVerification.username == user.username,
        OTPVerification.is_used == False
    ).update(
        {"is_used": True}
    )

    # Generate six-digit OTP

    otp = str(secrets.randbelow(900000) + 100000)

    # Hash OTP before storing it

    otp_hash = pbkdf2_sha256.hash(otp)

    verification = OTPVerification(
        username=user.username,
        otp_hash=otp_hash,
        expires_at=datetime.utcnow() + timedelta(
            minutes=OTP_EXPIRE_MINUTES
        ),
        attempts=0,
        is_used=False
    )

    db.add(verification)
    db.commit()

    try:

        # Send OTP through Gmail

        await send_otp_email(
            user.email,
            otp
        )

    except Exception:

        verification.is_used = True
        db.commit()

        raise


# -------------------------------------------------
# REGISTRATION
# -------------------------------------------------

@router.post("/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):

    db: Session = SessionLocal()

    try:

        username = username.strip()
        email = email.strip().lower()

        username_error = validate_username(username)
        password_error = validate_password(password)
        email_error = validate_email(email)

        if username_error:
            raise ValueError(username_error)

        if password_error:
            raise ValueError(password_error)

        if email_error:
            raise ValueError(email_error)

        # Check existing username

        existing_user = db.query(User).filter(
            User.username == username
        ).first()

        if existing_user:
            raise ValueError("Username already exists")

        # Check existing email

        existing_email = db.query(User).filter(
            User.email == email
        ).first()

        if existing_email:
            raise ValueError("Email already registered")

        # Prevent password reuse across different accounts.
        # Passwords remain stored only as PBKDF2 hashes.
        existing_password_hashes = db.query(User.password).all()

        for (stored_password_hash,) in existing_password_hashes:
            try:
                if pbkdf2_sha256.verify(password, stored_password_hash):
                    raise ValueError(
                        "This password is already used by another account. "
                        "Please choose a different password."
                    )
            except ValueError as error:
                if "already used by another account" in str(error):
                    raise
                # Skip malformed legacy hashes rather than breaking registration.
                continue

        # Create new user

        new_user = User(
            username=username,
            email=email,
            password=pbkdf2_sha256.hash(password),
            role="User"
        )

        db.add(new_user)
        db.commit()

        log_event(
            username=username,
            action="User Registration",
            status="Success"
        )

        return RedirectResponse(
            url="/login-page?message=Registration%20successful",
            status_code=303
        )

    except ValueError as error:

        db.rollback()

        return RedirectResponse(
            url=f"/login-page?error={quote_plus(str(error))}",
            status_code=303
        )

    except Exception:

        db.rollback()

        log_event(
            username=username,
            action="User Registration",
            status="Failed"
        )

        return RedirectResponse(
            url="/login-page?error=Registration%20failed",
            status_code=303
        )

    finally:

        db.close()


# -------------------------------------------------
# LOGIN - FIRST AUTHENTICATION FACTOR
# -------------------------------------------------

@router.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...)
):

    db: Session = SessionLocal()

    try:

        username = username.strip()

        user = db.query(User).filter(
            User.username == username
        ).first()

        # Verify username and password

        if not user or not pbkdf2_sha256.verify(
            password,
            user.password
        ):

            log_event(
                username=username,
                action="User Login",
                status="Failed"
            )

            return RedirectResponse(
                url="/login-page?error=Invalid%20credentials",
                status_code=303
            )

        # Check registered email

        if not user.email:

            return RedirectResponse(
                url="/add-email-page",
                status_code=303
            )

        # Generate and send OTP

        await generate_and_send_otp(
            db,
            user
        )

        # Create temporary signed login challenge

        challenge = otp_serializer.dumps(
            user.username
        )

        response = RedirectResponse(
            url="/verify-otp",
            status_code=303
        )

        response.set_cookie(
            key="pending_login",
            value=challenge,
            httponly=True,
            max_age=600,
            samesite="lax",
            secure=False
        )

        log_event(
            username=username,
            action="OTP Sent",
            status="Success"
        )

        return response

    except Exception:

        db.rollback()

        return RedirectResponse(
            url="/login-page?error=Unable%20to%20send%20OTP",
            status_code=303
        )

    finally:

        db.close()


# -------------------------------------------------
# OTP VERIFICATION PAGE
# -------------------------------------------------

@router.get("/verify-otp", response_class=HTMLResponse)
async def verify_otp_page(request: Request):

    challenge = request.cookies.get("pending_login")

    if not challenge:

        return RedirectResponse(
            url="/login-page?error=Please%20login%20again",
            status_code=303
        )

    try:

        otp_serializer.loads(
            challenge,
            max_age=600
        )

    except (BadSignature, SignatureExpired):

        response = RedirectResponse(
            url="/login-page?error=Login%20session%20expired",
            status_code=303
        )

        response.delete_cookie("pending_login")

        return response

    return templates.TemplateResponse(
        request=request,
        name="verify_otp.html",
        context={
            "error": None,
            "message": None
        }
    )


# -------------------------------------------------
# OTP VERIFICATION
# -------------------------------------------------

@router.post("/verify-otp")
async def verify_otp(
    request: Request,
    otp: str = Form(...)
):

    challenge = request.cookies.get("pending_login")

    if not challenge:

        return RedirectResponse(
            url="/login-page?error=Please%20login%20again",
            status_code=303
        )

    try:

        username = otp_serializer.loads(
            challenge,
            max_age=600
        )

    except (BadSignature, SignatureExpired):

        response = RedirectResponse(
            url="/login-page?error=Login%20session%20expired",
            status_code=303
        )

        response.delete_cookie("pending_login")

        return response

    db = SessionLocal()

    try:

        verification = db.query(OTPVerification).filter(
            OTPVerification.username == username,
            OTPVerification.is_used == False
        ).order_by(
            OTPVerification.created_at.desc()
        ).first()

        if not verification:

            raise ValueError("No active OTP found")

        # Check OTP expiry

        if verification.expires_at < datetime.utcnow():

            verification.is_used = True
            db.commit()

            raise ValueError(
                "OTP expired. Please request a new OTP"
            )

        # Check maximum attempts

        if verification.attempts >= OTP_MAX_ATTEMPTS:

            verification.is_used = True
            db.commit()

            raise ValueError(
                "Maximum OTP attempts exceeded"
            )

        # Validate OTP format

        if not otp.isdigit() or len(otp) != 6:

            verification.attempts += 1
            db.commit()

            raise ValueError("Invalid OTP")

        # Verify OTP hash

        if not pbkdf2_sha256.verify(
            otp,
            verification.otp_hash
        ):

            verification.attempts += 1
            db.commit()

            raise ValueError("Incorrect OTP")

        # Fetch user

        user = db.query(User).filter(
            User.username == username
        ).first()

        if not user:

            raise ValueError("User account not found")

        # Mark OTP as used

        verification.is_used = True
        db.commit()

        # Generate JWT only after successful OTP verification

        token = create_access_token(
            username=user.username,
            role=user.role
        )

        log_event(
            username=username,
            action="OTP Verification",
            status="Success"
        )

        log_event(
            username=username,
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
            samesite="lax",
            secure=False
        )

        response.delete_cookie("pending_login")

        return response

    except ValueError as error:

        return templates.TemplateResponse(
            request=request,
            name="verify_otp.html",
            context={
                "error": str(error),
                "message": None
            },
            status_code=400
        )

    finally:

        db.close()


# -------------------------------------------------
# RESEND OTP
# -------------------------------------------------

@router.post("/resend-otp")
async def resend_otp(request: Request):

    challenge = request.cookies.get("pending_login")

    if not challenge:

        return RedirectResponse(
            url="/login-page?error=Please%20login%20again",
            status_code=303
        )

    try:

        username = otp_serializer.loads(
            challenge,
            max_age=600
        )

    except (BadSignature, SignatureExpired):

        response = RedirectResponse(
            url="/login-page?error=Login%20session%20expired",
            status_code=303
        )

        response.delete_cookie("pending_login")

        return response

    db = SessionLocal()

    try:

        previous = db.query(OTPVerification).filter(
            OTPVerification.username == username
        ).order_by(
            OTPVerification.created_at.desc()
        ).first()

        # Resend cooldown

        if previous and (
            datetime.utcnow() - previous.created_at
        ).total_seconds() < OTP_RESEND_SECONDS:

            raise ValueError(
                "Please wait one minute before requesting another OTP"
            )

        user = db.query(User).filter(
            User.username == username
        ).first()

        if not user or not user.email:

            raise ValueError("Registered email not found")

        # Generate and send new OTP

        await generate_and_send_otp(
            db,
            user
        )

        log_event(
            username=username,
            action="OTP Resent",
            status="Success"
        )

        return RedirectResponse(
            url="/verify-otp",
            status_code=303
        )

    except ValueError as error:

        return templates.TemplateResponse(
            request=request,
            name="verify_otp.html",
            context={
                "error": str(error),
                "message": None
            },
            status_code=400
        )

    except Exception:

        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name="verify_otp.html",
            context={
                "error": "Unable to resend OTP",
                "message": None
            },
            status_code=500
        )

    finally:

        db.close()


# -------------------------------------------------
# EXISTING USER - ADD EMAIL PAGE
# -------------------------------------------------

@router.get("/add-email-page", response_class=HTMLResponse)
async def add_email_page():

    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Add Email - Zero Trust API Gateway</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #101827;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
            }

            .container {
                background: white;
                padding: 35px;
                border-radius: 12px;
                width: 90%;
                max-width: 380px;
            }

            h2 {
                color: #172554;
                text-align: center;
            }

            label {
                display: block;
                margin-top: 15px;
                margin-bottom: 6px;
            }

            input {
                width: 100%;
                padding: 11px;
                box-sizing: border-box;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
            }

            button {
                width: 100%;
                padding: 12px;
                margin-top: 22px;
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
            }

            a {
                display: block;
                text-align: center;
                margin-top: 18px;
                color: #2563eb;
            }
        </style>
    </head>

    <body>

        <div class="container">

            <h2>Add Email Address</h2>

            <p>
                Enter your existing account credentials and
                email address to enable OTP login.
            </p>

            <form action="/add-email" method="post">

                <label>Username</label>
                <input type="text" name="username" required>

                <label>Existing Password</label>
                <input type="password" name="password" required>

                <label>Email Address</label>
                <input type="email" name="email" required>

                <button type="submit">
                    Save Email
                </button>

            </form>

            <a href="/login-page">Back to Login</a>

        </div>

    </body>
    </html>
    """)


# -------------------------------------------------
# EXISTING USER - SAVE EMAIL
# -------------------------------------------------

@router.post("/add-email")
async def add_email(
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...)
):

    db = SessionLocal()

    try:

        username = username.strip()
        email = email.strip().lower()

        user = db.query(User).filter(
            User.username == username
        ).first()

        # Verify existing account credentials

        if not user or not pbkdf2_sha256.verify(
            password,
            user.password
        ):

            return HTMLResponse(
                "<h3>Invalid username or password.</h3>",
                status_code=401
            )

        if user.email:

            return HTMLResponse(
                "<h3>An email address is already registered.</h3>",
                status_code=400
            )

        email_error = validate_email(email)

        if email_error:

            return HTMLResponse(
                f"<h3>{email_error}</h3>",
                status_code=400
            )

        existing_email = db.query(User).filter(
            User.email == email
        ).first()

        if existing_email:

            return HTMLResponse(
                "<h3>This email address is already registered.</h3>",
                status_code=400
            )

        user.email = email

        db.commit()

        log_event(
            username=username,
            action="Email Address Added",
            status="Success"
        )

        return HTMLResponse("""
            <h3>Email address saved successfully.</h3>
            <p>You can now log in using OTP authentication.</p>
            <a href="/login-page">Go to Login</a>
        """)

    except Exception:

        db.rollback()

        return HTMLResponse(
            "<h3>Unable to save email address.</h3>",
            status_code=500
        )

    finally:

        db.close()


# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):

    token = request.cookies.get("access_token")

    if token is None:

        return RedirectResponse(
            url="/login-page?error=Please%20login%20first",
            status_code=303
        )

    user_data = verify_access_token(token)

    if user_data is None:

        response = RedirectResponse(
            url="/login-page?error=Session%20expired",
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


# -------------------------------------------------
# LOGOUT
# -------------------------------------------------

@router.get("/logout")
async def logout(request: Request):

    token = request.cookies.get("access_token")

    if token:

        user_data = verify_access_token(token)

        if user_data:

            log_event(
                username=user_data["username"],
                action="User Logout",
                status="Success"
            )

    response = RedirectResponse(
        url="/login-page?message=Logged%20out%20successfully",
        status_code=303
    )

    response.delete_cookie("access_token")
    response.delete_cookie("pending_login")

    return response

