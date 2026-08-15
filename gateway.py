import csv
import io
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    StreamingResponse
)
from fastapi.templating import Jinja2Templates
from passlib.hash import pbkdf2_sha256
from sqlalchemy import func

from anomaly_detector import run_anomaly_detection
from auth import (
    validate_password,
    validate_username,
    verify_access_token
)
from audit import log_event
from database import SessionLocal
from models import (
    APIAnalytics,
    AnomalyResult,
    AuditLog,
    Service,
    User
)

router = APIRouter(
    prefix="/gateway",
    tags=["Zero Trust Gateway"]
)

templates = Jinja2Templates(directory="templates")


def get_current_user(request: Request):
    token = request.cookies.get("access_token")

    if token is None:
        return None

    return verify_access_token(token)


def require_logged_in_user(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    return user_data


def require_admin(request: Request):
    user_data = require_logged_in_user(request)

    if user_data["role"].lower() != "admin":
        return None

    return user_data


def user_management_redirect(
    message: str | None = None,
    error: str | None = None
):
    if message:
        encoded_message = quote_plus(message)

        return RedirectResponse(
            url=(
                "/gateway/user-management?"
                f"message={encoded_message}"
            ),
            status_code=303
        )

    encoded_error = quote_plus(
        error or "Unable to complete operation"
    )

    return RedirectResponse(
        url=(
            "/gateway/user-management?"
            f"error={encoded_error}"
        ),
        status_code=303
    )


def service_management_redirect(
    message: str | None = None,
    error: str | None = None
):
    if message:
        encoded_message = quote_plus(message)

        return RedirectResponse(
            url=(
                "/gateway/service-management?"
                f"message={encoded_message}"
            ),
            status_code=303
        )

    encoded_error = quote_plus(
        error or "Unable to complete operation"
    )

    return RedirectResponse(
        url=(
            "/gateway/service-management?"
            f"error={encoded_error}"
        ),
        status_code=303
    )


@router.get("/status", response_class=HTMLResponse)
async def gateway_status(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url=(
                "/login-page?"
                "error=Please+login+to+access+the+gateway"
            ),
            status_code=303
        )

    log_event(
        username=user_data["username"],
        action="Gateway Status",
        status="Allowed"
    )

    return templates.TemplateResponse(
        request=request,
        name="gateway_status.html",
        context={
            "username": user_data["username"],
            "role": user_data["role"],
            "gateway_status": "Active",
            "authentication_status": "JWT Verified",
            "authorization_status": "Access Granted",
            "trust_status": "Identity Confirmed"
        }
    )


@router.get("/user-service", response_class=HTMLResponse)
async def user_service(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url=(
                "/login-page?"
                "error=Please+login+to+access+the+user+service"
            ),
            status_code=303
        )

    log_event(
        username=user_data["username"],
        action="User Service",
        status="Allowed"
    )

    return templates.TemplateResponse(
        request=request,
        name="user_service.html",
        context={
            "username": user_data["username"],
            "role": user_data["role"]
        }
    )


@router.get("/admin-service", response_class=HTMLResponse)
async def admin_service(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url=(
                "/login-page?"
                "error=Please+login+to+access+the+admin+service"
            ),
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Admin Panel",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    log_event(
        username=admin_data["username"],
        action="Admin Panel",
        status="Allowed"
    )

    return templates.TemplateResponse(
        request=request,
        name="admin_service.html",
        context={
            "username": admin_data["username"],
            "role": admin_data["role"]
        }
    )


# -------------------------------------------------
# ADMIN-ONLY SECURITY AUDIT LOGS
# -------------------------------------------------

@router.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs(
    request: Request,
    username: str = "",
    status_filter: str = ""
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Security Logs",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        query = db.query(AuditLog)

        cleaned_username = username.strip()
        cleaned_status = status_filter.strip()

        if cleaned_username:
            query = query.filter(
                AuditLog.username.ilike(
                    f"%{cleaned_username}%"
                )
            )

        if cleaned_status:
            query = query.filter(
                AuditLog.status == cleaned_status
            )

        logs = (
            query
            .order_by(AuditLog.timestamp.desc())
            .all()
        )

        total_logs = db.query(AuditLog).count()

        allowed_logs = (
            db.query(AuditLog)
            .filter(AuditLog.status == "Allowed")
            .count()
        )

        denied_logs = (
            db.query(AuditLog)
            .filter(AuditLog.status == "Denied")
            .count()
        )

        success_logs = (
            db.query(AuditLog)
            .filter(AuditLog.status == "Success")
            .count()
        )

        log_event(
            username=admin_data["username"],
            action="Viewed Security Logs",
            status="Allowed"
        )

        return templates.TemplateResponse(
            request=request,
            name="audit_logs.html",
            context={
                "username": admin_data["username"],
                "role": admin_data["role"],
                "logs": logs,
                "total_logs": total_logs,
                "allowed_logs": allowed_logs,
                "denied_logs": denied_logs,
                "success_logs": success_logs,
                "search_username": username,
                "selected_status": status_filter
            }
        )

    finally:
        db.close()


# -------------------------------------------------
# ADMIN-ONLY AUDIT REPORT EXPORT
# -------------------------------------------------

@router.get("/audit-logs/export-csv")
async def export_audit_logs_csv(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Export Audit Report",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        logs = (
            db.query(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .all()
        )

        output = io.StringIO(newline="")
        writer = csv.writer(output)

        writer.writerow([
            "ID",
            "Username",
            "Action",
            "Status",
            "Date and Time"
        ])

        for audit_log in logs:
            timestamp = ""

            if audit_log.timestamp:
                timestamp = audit_log.timestamp.strftime(
                    "%d-%m-%Y %H:%M:%S"
                )

            writer.writerow([
                audit_log.id,
                audit_log.username,
                audit_log.action,
                audit_log.status,
                timestamp
            ])

        csv_content = output.getvalue()
        output.close()

        log_event(
            username=admin_data["username"],
            action="Exported Audit Report",
            status="Success"
        )

        response = StreamingResponse(
            iter([csv_content]),
            media_type="text/csv; charset=utf-8"
        )

        response.headers["Content-Disposition"] = (
            "attachment; "
            "filename=security_audit_logs.csv"
        )

        return response

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action="Export Audit Report",
            status="Failed"
        )

        return RedirectResponse(
            url=(
                "/gateway/audit-logs?"
                "error=Unable+to+export+audit+report"
            ),
            status_code=303
        )

    finally:
        db.close()


# -------------------------------------------------
# ADMIN-ONLY USER CRUD
# -------------------------------------------------

@router.get("/user-management", response_class=HTMLResponse)
async def user_management(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="User Management",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        users = (
            db.query(User)
            .order_by(User.id.asc())
            .all()
        )

        return templates.TemplateResponse(
            request=request,
            name="user_management.html",
            context={
                "username": admin_data["username"],
                "role": admin_data["role"],
                "users": users,
                "message": request.query_params.get("message"),
                "error": request.query_params.get("error")
            }
        )

    finally:
        db.close()


@router.post("/user-management/create")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...)
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Create User",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    username = username.strip()
    password = password.strip()
    role = role.strip().title()

    username_error = validate_username(username)

    if username_error:
        return user_management_redirect(
            error=username_error
        )

    password_error = validate_password(password)

    if password_error:
        return user_management_redirect(
            error=password_error
        )

    if role not in ["Admin", "User"]:
        role = "User"

    db = SessionLocal()

    try:
        existing_user = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if existing_user:
            return user_management_redirect(
                error="Username already exists"
            )

        new_user = User(
            username=username,
            password=pbkdf2_sha256.hash(password),
            role=role
        )

        db.add(new_user)
        db.commit()

        log_event(
            username=admin_data["username"],
            action=f"Created user: {username}",
            status="Success"
        )

        return user_management_redirect(
            message="User created successfully"
        )

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action=f"Create user failed: {username}",
            status="Failed"
        )

        return user_management_redirect(
            error="Unable to create user"
        )

    finally:
        db.close()


@router.post("/user-management/{user_id}/update")
async def update_user(
    user_id: int,
    request: Request,
    username: str = Form(...),
    role: str = Form(...),
    new_password: str = Form("")
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Update User",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    username = username.strip()
    role = role.strip().title()
    new_password = new_password.strip()

    username_error = validate_username(username)

    if username_error:
        return user_management_redirect(
            error=username_error
        )

    if new_password:
        password_error = validate_password(
            new_password
        )

        if password_error:
            return user_management_redirect(
                error=password_error
            )

    if role not in ["Admin", "User"]:
        role = "User"

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        if user is None:
            return user_management_redirect(
                error="User not found"
            )

        duplicate_user = (
            db.query(User)
            .filter(
                User.username == username,
                User.id != user_id
            )
            .first()
        )

        if duplicate_user:
            return user_management_redirect(
                error="Username already exists"
            )

        old_username = user.username

        user.username = username
        user.role = role

        if new_password:
            user.password = pbkdf2_sha256.hash(
                new_password
            )

        db.commit()

        log_event(
            username=admin_data["username"],
            action=(
                f"Updated user: {old_username} "
                f"to {username}"
            ),
            status="Success"
        )

        return user_management_redirect(
            message="User updated successfully"
        )

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action=f"Update user failed: {user_id}",
            status="Failed"
        )

        return user_management_redirect(
            error="Unable to update user"
        )

    finally:
        db.close()


@router.post("/user-management/{user_id}/delete")
async def delete_user(
    user_id: int,
    request: Request
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Delete User",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        if user is None:
            return user_management_redirect(
                error="User not found"
            )

        if user.username == admin_data["username"]:
            return user_management_redirect(
                error=(
                    "You cannot delete your own "
                    "administrator account"
                )
            )

        deleted_username = user.username

        db.delete(user)
        db.commit()

        log_event(
            username=admin_data["username"],
            action=f"Deleted user: {deleted_username}",
            status="Success"
        )

        return user_management_redirect(
            message="User deleted successfully"
        )

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action=f"Delete user failed: {user_id}",
            status="Failed"
        )

        return user_management_redirect(
            error="Unable to delete user"
        )

    finally:
        db.close()

# -------------------------------------------------
# ADMIN-ONLY SERVICE CRUD
# -------------------------------------------------

@router.get("/service-management", response_class=HTMLResponse)
async def service_management(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Service Management",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        services = (
            db.query(Service)
            .order_by(Service.id.asc())
            .all()
        )

        return templates.TemplateResponse(
            request=request,
            name="service_management.html",
            context={
                "username": admin_data["username"],
                "role": admin_data["role"],
                "services": services,
                "message": request.query_params.get("message"),
                "error": request.query_params.get("error")
            }
        )

    finally:
        db.close()


@router.post("/service-management/create")
async def create_service(
    request: Request,
    name: str = Form(...),
    endpoint: str = Form(...),
    service_status: str = Form(...),
    authentication: str = Form(...),
    authorization: str = Form(...)
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Create Service",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    name = name.strip()
    endpoint = endpoint.strip()
    service_status = service_status.strip()
    authentication = authentication.strip()
    authorization = authorization.strip()

    if not name or not endpoint:
        return service_management_redirect(
            error="Service name and endpoint are required"
        )

    if not endpoint.startswith("/"):
        return service_management_redirect(
            error="Service endpoint must begin with /"
        )

    if service_status not in [
        "Online",
        "Offline",
        "Maintenance"
    ]:
        service_status = "Online"

    if authentication not in [
        "JWT",
        "API Key",
        "OAuth2"
    ]:
        authentication = "JWT"

    if authorization not in [
        "Authenticated Users",
        "Administrator Only"
    ]:
        authorization = "Authenticated Users"

    db = SessionLocal()

    try:
        existing_service = (
            db.query(Service)
            .filter(Service.name == name)
            .first()
        )

        if existing_service:
            return service_management_redirect(
                error="Service already exists"
            )

        duplicate_endpoint = (
            db.query(Service)
            .filter(Service.endpoint == endpoint)
            .first()
        )

        if duplicate_endpoint:
            return service_management_redirect(
                error="Service endpoint already exists"
            )

        new_service = Service(
            name=name,
            endpoint=endpoint,
            status=service_status,
            authentication=authentication,
            authorization=authorization
        )

        db.add(new_service)
        db.commit()

        log_event(
            username=admin_data["username"],
            action=f"Created service: {name}",
            status="Success"
        )

        return service_management_redirect(
            message="Service created successfully"
        )

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action=f"Create service failed: {name}",
            status="Failed"
        )

        return service_management_redirect(
            error="Unable to create service"
        )

    finally:
        db.close()


@router.post("/service-management/{service_id}/update")
async def update_service(
    service_id: int,
    request: Request,
    name: str = Form(...),
    endpoint: str = Form(...),
    service_status: str = Form(...),
    authentication: str = Form(...),
    authorization: str = Form(...)
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Update Service",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    name = name.strip()
    endpoint = endpoint.strip()
    service_status = service_status.strip()
    authentication = authentication.strip()
    authorization = authorization.strip()

    if not name or not endpoint:
        return service_management_redirect(
            error="Service name and endpoint are required"
        )

    if not endpoint.startswith("/"):
        return service_management_redirect(
            error="Service endpoint must begin with /"
        )

    if service_status not in [
        "Online",
        "Offline",
        "Maintenance"
    ]:
        service_status = "Online"

    if authentication not in [
        "JWT",
        "API Key",
        "OAuth2"
    ]:
        authentication = "JWT"

    if authorization not in [
        "Authenticated Users",
        "Administrator Only"
    ]:
        authorization = "Authenticated Users"

    db = SessionLocal()

    try:
        service = (
            db.query(Service)
            .filter(Service.id == service_id)
            .first()
        )

        if service is None:
            return service_management_redirect(
                error="Service not found"
            )

        duplicate_service = (
            db.query(Service)
            .filter(
                Service.name == name,
                Service.id != service_id
            )
            .first()
        )

        if duplicate_service:
            return service_management_redirect(
                error="Service name already exists"
            )

        duplicate_endpoint = (
            db.query(Service)
            .filter(
                Service.endpoint == endpoint,
                Service.id != service_id
            )
            .first()
        )

        if duplicate_endpoint:
            return service_management_redirect(
                error="Service endpoint already exists"
            )

        old_name = service.name

        service.name = name
        service.endpoint = endpoint
        service.status = service_status
        service.authentication = authentication
        service.authorization = authorization

        db.commit()

        log_event(
            username=admin_data["username"],
            action=f"Updated service: {old_name}",
            status="Success"
        )

        return service_management_redirect(
            message="Service updated successfully"
        )

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action=f"Update service failed: {service_id}",
            status="Failed"
        )

        return service_management_redirect(
            error="Unable to update service"
        )

    finally:
        db.close()


@router.post("/service-management/{service_id}/delete")
async def delete_service(
    service_id: int,
    request: Request
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Delete Service",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        service = (
            db.query(Service)
            .filter(Service.id == service_id)
            .first()
        )

        if service is None:
            return service_management_redirect(
                error="Service not found"
            )

        deleted_service_name = service.name

        db.delete(service)
        db.commit()

        log_event(
            username=admin_data["username"],
            action=f"Deleted service: {deleted_service_name}",
            status="Success"
        )

        return service_management_redirect(
            message="Service deleted successfully"
        )

    except Exception:
        db.rollback()

        log_event(
            username=admin_data["username"],
            action=f"Delete service failed: {service_id}",
            status="Failed"
        )

        return service_management_redirect(
            error="Unable to delete service"
        )

    finally:
        db.close()


# -------------------------------------------------
# ADMIN-ONLY API ANALYTICS AND MONITORING
# -------------------------------------------------

@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_dashboard(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url=(
                "/login-page?"
                "error=Please+login+to+view+monitoring"
            ),
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="API Monitoring Dashboard",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        total_users = db.query(User).count()
        total_services = db.query(Service).count()
        total_logs = db.query(AuditLog).count()
        total_api_requests = db.query(APIAnalytics).count()

        get_requests = (
            db.query(APIAnalytics)
            .filter(APIAnalytics.method == "GET")
            .count()
        )

        post_requests = (
            db.query(APIAnalytics)
            .filter(APIAnalytics.method == "POST")
            .count()
        )

        allowed_requests = (
            db.query(APIAnalytics)
            .filter(APIAnalytics.status == "Allowed")
            .count()
        )

        denied_requests = (
            db.query(APIAnalytics)
            .filter(APIAnalytics.status == "Denied")
            .count()
        )

        rate_limited_requests = (
            db.query(APIAnalytics)
            .filter(
                APIAnalytics.status == "Rate Limited"
            )
            .count()
        )

        online_services = (
            db.query(Service)
            .filter(Service.status == "Online")
            .count()
        )

        offline_services = (
            db.query(Service)
            .filter(Service.status == "Offline")
            .count()
        )

        maintenance_services = (
            db.query(Service)
            .filter(Service.status == "Maintenance")
            .count()
        )

        endpoint_statistics = (
            db.query(
                APIAnalytics.endpoint,
                func.count(APIAnalytics.id).label(
                    "request_count"
                )
            )
            .group_by(APIAnalytics.endpoint)
            .order_by(
                func.count(APIAnalytics.id).desc()
            )
            .all()
        )

        endpoint_labels = [
            row.endpoint
            for row in endpoint_statistics
        ]

        endpoint_values = [
            row.request_count
            for row in endpoint_statistics
        ]

        if endpoint_statistics:
            most_used_endpoint = (
                endpoint_statistics[0].endpoint
            )

            most_used_count = (
                endpoint_statistics[0].request_count
            )

        else:
            most_used_endpoint = "No requests recorded"
            most_used_count = 0

        recent_api_requests = (
            db.query(APIAnalytics)
            .order_by(APIAnalytics.timestamp.desc())
            .limit(10)
            .all()
        )

        log_event(
            username=admin_data["username"],
            action="API Monitoring Dashboard",
            status="Allowed"
        )

        if offline_services > 0:
            gateway_health = "Attention Required"

        elif maintenance_services > 0:
            gateway_health = "Maintenance"

        else:
            gateway_health = "Healthy"

        return templates.TemplateResponse(
            request=request,
            name="monitoring_dashboard.html",
            context={
                "username": admin_data["username"],
                "role": admin_data["role"],

                "total_users": total_users,
                "total_services": total_services,
                "total_logs": total_logs,

                "total_api_requests": total_api_requests,
                "get_requests": get_requests,
                "post_requests": post_requests,
                "allowed_requests": allowed_requests,
                "denied_requests": denied_requests,
                "rate_limited_requests": (
                    rate_limited_requests
                ),

                "online_services": online_services,
                "offline_services": offline_services,
                "maintenance_services": (
                    maintenance_services
                ),

                "most_used_endpoint": most_used_endpoint,
                "most_used_count": most_used_count,

                "endpoint_labels": endpoint_labels,
                "endpoint_values": endpoint_values,

                "recent_api_requests": recent_api_requests,
                "gateway_health": gateway_health
            }
        )

    finally:
        db.close()

# -------------------------------------------------
# ADMIN-ONLY ML ANOMALY DETECTION
# -------------------------------------------------

@router.get(
    "/anomaly-detection",
    response_class=HTMLResponse
)
async def anomaly_detection_dashboard(
    request: Request
):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Anomaly Detection Dashboard",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    db = SessionLocal()

    try:
        results = (
            db.query(AnomalyResult)
            .order_by(
                AnomalyResult.timestamp.desc()
            )
            .all()
        )

        total_results = (
            db.query(AnomalyResult)
            .count()
        )

        normal_count = (
            db.query(AnomalyResult)
            .filter(
                AnomalyResult.result == "Normal"
            )
            .count()
        )

        anomaly_count = (
            db.query(AnomalyResult)
            .filter(
                AnomalyResult.result == "Anomaly"
            )
            .count()
        )

        log_event(
            username=admin_data["username"],
            action="Viewed ML Anomaly Detection",
            status="Allowed"
        )

        return templates.TemplateResponse(
            request=request,
            name="anomaly_detection.html",
            context={
                "username": admin_data["username"],
                "role": admin_data["role"],
                "results": results,
                "total_results": total_results,
                "normal_count": normal_count,
                "anomaly_count": anomaly_count,
                "message": request.query_params.get(
                    "message"
                ),
                "error": request.query_params.get(
                    "error"
                )
            }
        )

    except Exception as error:
        log_event(
            username=admin_data["username"],
            action="Viewed ML Anomaly Detection",
            status="Failed"
        )

        return RedirectResponse(
            url=(
                "/gateway/admin-service?"
                f"error={quote_plus(str(error))}"
            ),
            status_code=303
        )

    finally:
        db.close()


@router.post("/anomaly-detection/run")
async def run_detection(request: Request):
    user_data = get_current_user(request)

    if user_data is None:
        return RedirectResponse(
            url="/login-page?error=Please+login+first",
            status_code=303
        )

    admin_data = require_admin(request)

    if admin_data is None:
        log_event(
            username=user_data["username"],
            action="Run ML Anomaly Detection",
            status="Denied"
        )

        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "username": user_data["username"],
                "role": user_data["role"]
            },
            status_code=403
        )

    detection_result = run_anomaly_detection()

    if not detection_result.get("success"):
        error_message = detection_result.get(
            "message",
            "Unable to run anomaly detection"
        )

        log_event(
            username=admin_data["username"],
            action="Ran ML Anomaly Detection",
            status="Failed"
        )

        return RedirectResponse(
            url=(
                "/gateway/anomaly-detection?"
                f"error={quote_plus(error_message)}"
            ),
            status_code=303
        )

    analysed_users = detection_result.get(
        "analysed_users",
        0
    )

    anomaly_count = detection_result.get(
        "anomaly_count",
        0
    )

    success_message = (
        f"ML detection completed. "
        f"Analysed {analysed_users} users and "
        f"detected {anomaly_count} anomalies."
    )

    log_event(
        username=admin_data["username"],
        action=(
            f"Ran ML Anomaly Detection: "
            f"{anomaly_count} anomalies detected"
        ),
        status="Success"
    )

    return RedirectResponse(
        url=(
            "/gateway/anomaly-detection?"
            f"message={quote_plus(success_message)}"
        ),
        status_code=303
    )