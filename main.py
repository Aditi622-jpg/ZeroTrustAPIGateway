from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from analytics import log_api_request
from database import engine
from models import Base
from auth import (
    router as auth_router,
    verify_access_token
)
from gateway import router as gateway_router
from rate_limiter import is_rate_limited


app = FastAPI(
    title="Zero Trust API Gateway",
    description="JWT authentication and role-based access control project",
    version="1.0"
)


# Create database tables
Base.metadata.create_all(bind=engine)


# Connect static files
app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# Connect HTML templates
templates = Jinja2Templates(directory="templates")


# Add authentication routes
app.include_router(auth_router)


# Add Zero Trust gateway routes
app.include_router(gateway_router)


@app.middleware("http")
async def security_and_analytics_middleware(
    request: Request,
    call_next
):
    endpoint = request.url.path
    method = request.method

    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    username = "Anonymous"

    token = request.cookies.get("access_token")

    if token:
        user_data = verify_access_token(token)

        if user_data:
            username = user_data["username"]

    # -------------------------------------------------
    # LOGIN RATE LIMIT
    # Maximum 5 login requests per minute per IP
    # -------------------------------------------------

    if endpoint == "/login" and method == "POST":

        login_identifier = f"login:{client_ip}"

        if is_rate_limited(
            identifier=login_identifier,
            limit=5,
            window_seconds=60
        ):
            log_api_request(
                username=username,
                endpoint=endpoint,
                method=method,
                request_status="Rate Limited",
                response_code=429
            )

            return JSONResponse(
                status_code=429,
                content={
                    "message": (
                        "Too many login attempts. "
                        "Please wait one minute and try again."
                    )
                }
            )

    # -------------------------------------------------
    # REGISTRATION RATE LIMIT
    # Maximum 3 registration requests per minute per IP
    # -------------------------------------------------

    elif endpoint == "/register" and method == "POST":

        register_identifier = f"register:{client_ip}"

        if is_rate_limited(
            identifier=register_identifier,
            limit=3,
            window_seconds=60
        ):
            log_api_request(
                username=username,
                endpoint=endpoint,
                method=method,
                request_status="Rate Limited",
                response_code=429
            )

            return JSONResponse(
                status_code=429,
                content={
                    "message": (
                        "Too many registration attempts. "
                        "Please wait one minute and try again."
                    )
                }
            )

    # -------------------------------------------------
    # GATEWAY RATE LIMIT
    # Maximum 30 gateway requests per minute per user
    # -------------------------------------------------

    elif endpoint.startswith("/gateway"):

        gateway_identifier = (
            f"gateway:{client_ip}:{username}"
        )

        if is_rate_limited(
            identifier=gateway_identifier,
            limit=30,
            window_seconds=60
        ):
            log_api_request(
                username=username,
                endpoint=endpoint,
                method=method,
                request_status="Rate Limited",
                response_code=429
            )

            return JSONResponse(
                status_code=429,
                content={
                    "message": (
                        "API request limit exceeded. "
                        "Please wait one minute and try again."
                    )
                }
            )

    # Process the request normally
    response = await call_next(request)

    # -------------------------------------------------
    # API ANALYTICS LOGGING
    # -------------------------------------------------

    if (
        endpoint.startswith("/gateway")
        or endpoint in ["/login", "/register"]
    ):
        if response.status_code == 429:
            request_status = "Rate Limited"

        elif response.status_code < 400:
            request_status = "Allowed"

        else:
            request_status = "Denied"

        log_api_request(
            username=username,
            endpoint=endpoint,
            method=method,
            request_status=request_status,
            response_code=response.status_code
        )

    return response


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="home.html"
    )


@app.get("/login-page", response_class=HTMLResponse)
async def login_page(request: Request):
    message = request.query_params.get("message")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "message": message,
            "error": error
        }
    )


@app.get("/register-page", response_class=HTMLResponse)
async def register_page(request: Request):
    message = request.query_params.get("message")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "message": message,
            "error": error
        }
    )