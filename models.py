from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    Boolean
)

from database import Base


# USER MODEL
class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        unique=True,
        index=True
    )

    # Email address for Gmail OTP verification
    email = Column(
        String,
        unique=True,
        index=True,
        nullable=True
    )

    password = Column(String)

    role = Column(String)


# OTP VERIFICATION MODEL
class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        nullable=False,
        index=True
    )

    otp_hash = Column(
        String,
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    attempts = Column(
        Integer,
        default=0
    )

    is_used = Column(
        Boolean,
        default=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# AUDIT LOG MODEL
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(String)

    action = Column(String)

    status = Column(String)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )


# SERVICE MODEL
class Service(Base):
    __tablename__ = "services"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        unique=True,
        nullable=False
    )

    endpoint = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        default="Online"
    )

    authentication = Column(
        String,
        default="JWT"
    )

    authorization = Column(
        String,
        default="Authenticated Users"
    )


# API ANALYTICS MODEL
class APIAnalytics(Base):
    __tablename__ = "api_analytics"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        default="Anonymous"
    )

    endpoint = Column(
        String,
        nullable=False
    )

    method = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        nullable=False
    )

    response_code = Column(
        Integer,
        nullable=False
    )

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )


# MACHINE LEARNING ANOMALY DETECTION MODEL
class AnomalyResult(Base):
    __tablename__ = "anomaly_results"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        nullable=False
    )

    total_requests = Column(
        Integer,
        default=0
    )

    denied_requests = Column(
        Integer,
        default=0
    )

    failed_logins = Column(
        Integer,
        default=0
    )

    rate_limited_requests = Column(
        Integer,
        default=0
    )

    unique_endpoints = Column(
        Integer,
        default=0
    )

    result = Column(
        String,
        default="Normal"
    )

    anomaly_score = Column(
        String,
        default="0"
    )

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )


# IP-BASED ACCESS CONTROL MODEL
class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    ip_address = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    reason = Column(
        Text,
        nullable=True
    )

    blocked_by = Column(
        String,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    is_active = Column(
        Boolean,
        default=True
    )