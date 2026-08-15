# 🔐 Zero Trust API Gateway

A security-focused **Zero Trust API Gateway** built using **FastAPI, Python, SQLAlchemy, SQLite, HTML, CSS, Jinja2, JWT authentication, and Scikit-learn**.

The project follows the **Zero Trust principle — "Never Trust, Always Verify."** Every protected request is verified before access is granted based on authentication, authorization, user role, and security checks.

The system also includes API monitoring, audit logging, administrative controls, and machine learning-based anomaly detection.

---

# 📌 Project Overview

Modern applications rely heavily on APIs for communication between users, services, and databases. If API access is not properly protected, unauthorized users may gain access to sensitive resources.

This project implements a **Zero Trust API Gateway** that verifies each request before allowing access to protected services.

The gateway performs:

* User authentication
* JWT token verification
* Role verification
* Access control
* Security logging
* API monitoring
* Anomaly detection

---

# ✨ Key Features

## 🔑 Secure Authentication

* User registration and secure login
* JWT-based authentication
* Username validation
* Strong password policy
* Real-time password strength indicator
* Secure password hashing using PBKDF2

---

## 🔒 Password Security

User passwords are not stored directly in the database.

Passwords are securely hashed using **PBKDF2 through Passlib** before being stored.

---

## 👥 Role-Based Access Control (RBAC)

The system provides separate permissions for **Admin** and **User** roles.

### User

Authenticated users can access authorized user services and protected resources.

### Admin

Administrators can:

* Manage users
* Manage services
* View security logs
* Monitor gateway activity
* Access administrative services

---

# 🛡️ Zero Trust Verification

Every protected request passes through a security verification process.

```text id="wt0l5i"
API Request
     ↓
JWT Verification
     ↓
User Verification
     ↓
Role / Permission Check
     ↓
Access Decision
    ↙     ↘
 ALLOW    DENY
```

This follows the Zero Trust concept that authentication alone should not automatically provide access to every resource.

---

# 🌐 Protected Services

The project includes:

* Gateway Status
* User Service
* Admin Service
* User Management
* Service Management
* Monitoring Dashboard
* Security Audit Logs

---

# 👨‍💻 Admin User Management

Administrators can perform CRUD operations on users:

* Create users
* View users
* Update users
* Delete users
* Manage user roles

---

# ⚙️ Service Management

Administrators can manage protected services and their security configurations.

---

# 📋 Security Audit Logging

Important security activities are recorded, including:

* Successful logins
* Failed login attempts
* Gateway access
* Protected service access
* Access denied events
* Administrative actions
* User management operations
* System events

These logs can assist with security monitoring and investigation.

---

# 📊 API Monitoring Dashboard

The monitoring dashboard provides information about:

* Total API requests
* Gateway health
* Service status
* Endpoint usage
* Recent API activity
* Security events
* User activity

---

# 📁 CSV Export

Security audit logs can be exported in **CSV format** for:

* Security analysis
* Reporting
* Compliance
* Documentation
* Incident investigation

---

# 🤖 Machine Learning-Based Anomaly Detection

The project integrates **Scikit-learn** for anomaly detection.

The system analyzes application activity to identify potentially unusual or suspicious access patterns.

Examples include:

* Excessive request activity
* Unusual API usage
* Unexpected access patterns
* Abnormal user activity

---

# 🏗️ System Architecture

```text id="10l3mh"
                User / Administrator
                        ↓
               HTML / CSS Dashboard
                        ↓
                  FastAPI Backend
                        ↓
             Zero Trust API Gateway
                        ↓
            JWT + Role Verification
                        ↓
                Access Decision
                   ↙        ↘
               Granted     Denied
                  ↓
            Protected Service
                  ↓
              SQLAlchemy
                  ↓
                SQLite
```

---

# 🛠️ Technologies Used

| Technology   | Purpose                            |
| ------------ | ---------------------------------- |
| Python       | Core programming language          |
| FastAPI      | Backend and API development        |
| Uvicorn      | ASGI server                        |
| SQLAlchemy   | Database ORM                       |
| SQLite       | Application database               |
| JWT          | Token-based authentication         |
| Passlib      | Password security                  |
| PBKDF2       | Password hashing                   |
| Jinja2       | Dynamic HTML templates             |
| HTML         | Frontend structure                 |
| CSS          | Frontend styling                   |
| Scikit-learn | Machine learning anomaly detection |

---

# 📦 Dependencies

Install the required dependencies:

```bash id="5w9fhr"
pip install fastapi uvicorn sqlalchemy jinja2 python-multipart passlib pyjwt scikit-learn numpy pandas
```

### requirements.txt

```text id="mhudrd"
fastapi
uvicorn
sqlalchemy
jinja2
python-multipart
passlib
PyJWT
scikit-learn
numpy
pandas
```

Dependencies can also be installed using:

```bash id="tcfgu6"
pip install -r requirements.txt
```

---

# ▶️ Run the Application

Run the FastAPI application using:

```bash id="z0rlyi"
python -m uvicorn app:app --reload
```

After the server starts, open:

```text id="y9ub3r"
http://127.0.0.1:8000
```

### API Documentation

FastAPI Swagger documentation can be accessed at:

```text id="9fbr91"
http://127.0.0.1:8000/docs
```

---

# 🔄 Application Workflow

```text id="fxykrv"
User Registration
       ↓
Input Validation
       ↓
Password Hashing
       ↓
SQLite Database
       ↓
User Login
       ↓
JWT Generated
       ↓
Protected API Request
       ↓
Zero Trust Gateway
       ↓
JWT + Role + Permission Verification
       ↓
Access Granted / Denied
       ↓
Security Event Logged
       ↓
Monitoring
       ↓
Anomaly Detection
```

---

# 📂 Main Project Modules

### Authentication Module

Handles registration, login, password hashing, JWT generation, and authentication.

### Authorization Module

Handles user roles, permissions, and access control.

### Gateway Module

Acts as the central security layer for protected API requests.

### User Management Module

Allows administrators to manage users.

### Service Management Module

Allows administrators to manage protected services.

### Audit Logging Module

Records important security events and activities.

### Monitoring Module

Tracks API requests, gateway health, endpoint usage, service status, and recent activity.

### Anomaly Detection Module

Uses machine learning to identify potentially unusual activity.

---

# 🔐 Security Features

* Zero Trust access verification
* JWT authentication
* PBKDF2 password hashing
* Role-Based Access Control
* Protected API endpoints
* Admin-only operations
* Strong password policy
* Security audit logging
* API monitoring
* Access-denied tracking
* ML-based anomaly detection

---

# 🎯 Project Objective

The objective of this project is to demonstrate the application of **Zero Trust security principles to API-based systems**.

The system combines:

**Authentication + Authorization + Access Verification + Monitoring + Audit Logging + Anomaly Detection**

to provide multiple layers of security for protected API services.

---

# 🚀 Future Enhancements

* Multi-Factor Authentication
* OAuth2 integration
* Refresh tokens
* JWT token revocation
* API rate limiting
* HTTPS/TLS
* Real-time security alerts
* SIEM integration
* Docker deployment
* Cloud deployment
* Prometheus and Grafana monitoring
* Advanced anomaly detection models

---

# 📚 Learning Outcomes

The project demonstrates:

* Zero Trust Architecture
* API Security
* Secure Authentication
* Authorization
* JWT
* RBAC
* Password Security
* FastAPI Development
* Database Management
* Audit Logging
* Security Monitoring
* Machine Learning for Cybersecurity

---

# 👩‍💻 Author

**Aditi Bajpai**

B.Tech – Computer Science and Engineering
Cyber Security
