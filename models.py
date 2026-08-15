from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text
)

from database import Base


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

    password = Column(String)

    role = Column(String)


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

# -------------------------------------------------
# MACHINE LEARNING ANOMALY DETECTION
# -------------------------------------------------

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