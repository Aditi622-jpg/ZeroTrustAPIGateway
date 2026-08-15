# 🔐 Zero Trust API Gateway

A security-focused **Zero Trust API Gateway** developed using **FastAPI, Python, SQLAlchemy, SQLite, HTML, CSS, Jinja2, JWT authentication, and Scikit-learn**.

The project follows the Zero Trust security principle:

> **Never Trust, Always Verify**

Instead of automatically trusting a user after login, the system verifies authentication, authorization, roles, and permissions before allowing access to protected services.

The application also provides **security audit logging, API monitoring, administrative controls, analytics, and machine learning-based anomaly detection**.

---

## 📌 Project Overview

Modern applications rely heavily on APIs for communication between users, applications, databases, and backend services. Improperly protected APIs can expose sensitive resources to unauthorized users.

The **Zero Trust API Gateway** acts as a centralized security layer between users and protected services.

When a user attempts to access a protected resource, the gateway performs security checks before deciding whether the request should be allowed or denied.

The gateway provides:

* Secure user authentication
* JWT token verification
* Role-Based Access Control (RBAC)
* Zero Trust access verification
* Protected API services
* Administrative controls
* Security audit logging
* API activity monitoring
* Security analytics
* Machine learning-based anomaly detection
* CSV audit log export

---

# ✨ Key Features

## 🔑 Secure Authentication

The application provides secure registration and login functionality.

Features include:

* User registration
* Secure login
* JWT-based authentication
* Username validation
* Strong password requirements
* Real-time password strength indicator
* Secure password hashing using PBKDF2

After successful login, authentication information is used to verify access to protected resources.

---

## 🔒 Password Security

Passwords are not stored directly as plain text.

The application uses **PBKDF2 through Passlib** to securely hash user passwords before they are stored.

During login, the entered password is verified against the stored password hash.

---

## 🎫 JWT Authentication

The project uses **JSON Web Tokens (JWT)** for authentication.

After successful authentication, a JWT can be used to identify and verify the user when accessing protected resources.

This allows the gateway to determine whether the request comes from an authenticated user.

---

## 👥 Role-Based Access Control (RBAC)

The application separates users according to their roles.

### 👤 User

Authenticated users can access services and resources that are authorized for normal users.

### 👨‍💻 Admin

Administrators have additional privileges, including:

* User management
* Service management
* Administrative services
* Security audit log access
* API monitoring
* Security analytics

A normal user cannot access resources restricted to administrators.

---

# 🛡️ Zero Trust Access Verification

Every protected request goes through security verification before access is granted.

```text
User Request
     ↓
FastAPI Endpoint
     ↓
Zero Trust Gateway
     ↓
JWT / Authentication Check
     ↓
User Identity Verification
     ↓
Role & Permission Check
     ↓
Access Decision
    ↙             ↘
GRANTED          DENIED
   ↓
Protected Service
```

This means that simply being logged in does not automatically give a user access to every service.

---

# 🌐 API Gateway

The **API Gateway** acts as the central security checkpoint for protected services.

The frontend communicates with the FastAPI backend through application routes/endpoints.

Before protected functionality is accessed, the gateway can perform checks such as:

* Is the user authenticated?
* Is the authentication information valid?
* What role does the user have?
* Does the user have permission to access this service?
* Should the request be allowed or denied?
* Should the activity be recorded for security monitoring?

This creates a centralized security layer for application access.

---

# 🌐 Protected Services

The application contains multiple protected areas, including:

### Gateway Status

Displays information about the operational status of the API Gateway.

### User Service

Provides protected functionality for authenticated and authorized users.

### Admin Service

Provides restricted functionality that can only be accessed by administrators.

---

# 👨‍💻 Admin User Management

Administrators can manage users from the administrative interface.

Supported operations include:

* Create users
* View users
* Update user information
* Delete users
* Manage user roles

This provides centralized control over application users.

---

# ⚙️ Service Management

The administrator can manage services protected by the Zero Trust Gateway.

Service management provides control over protected resources and their associated security settings.

---

# 📋 Security Audit Logging

The application records important security-related events.

Examples include:

* Successful login attempts
* Failed login attempts
* Gateway access
* Protected service access
* Access denied events
* Administrative actions
* User management actions
* System events

Audit logging provides a record of important activity occurring within the application.

---

# 📊 API Monitoring & Analytics

The application includes monitoring and analytics functionality for observing API and gateway activity.

Information can include:

* API request statistics
* Gateway health
* Service status
* Endpoint usage
* Recent API activity
* Security events
* User activity

This allows administrators to understand how protected services are being accessed.

---

# 🤖 Machine Learning-Based Anomaly Detection

The project integrates **Scikit-learn** for anomaly detection.

The anomaly detection component analyzes application activity to identify potentially unusual access patterns.

Examples of activity that may be identified as unusual include:

* Excessive request activity
* Abnormal API usage
* Unexpected user behavior
* Unusual access patterns

Suspicious activity can then be highlighted for further security investigation.

---

# 📁 CSV Audit Log Export

Security audit logs can be exported in **CSV format**.

Exported logs can be used for:

* Security analysis
* Reporting
* Documentation
* Compliance-related activities
* Incident investigation

---

# 🏗️ System Architecture

```text
               User / Administrator
                       ↓
              HTML / CSS Frontend
                       ↓
                Jinja2 Templates
                       ↓
                 FastAPI Backend
                       ↓
              Zero Trust Gateway
                       ↓
          ┌────────────┼────────────┐
          ↓            ↓            ↓
    Authentication    RBAC       Audit Logging
          ↓            ↓
          └──────┬─────┘
                 ↓
           Access Decision
             ↙       ↘
          ALLOW      DENY
            ↓
      Protected Service
            ↓
        SQLAlchemy
            ↓
          SQLite
```

Monitoring, analytics, and anomaly detection provide additional visibility into application activity.

---

# 🔄 Application Workflow

```text
Registration
     ↓
Input Validation
     ↓
Password Hashing
     ↓
Database Storage
     ↓
Login
     ↓
Credential Verification
     ↓
JWT Authentication
     ↓
Protected Request
     ↓
Zero Trust Gateway
     ↓
Authentication Verification
     ↓
Role / Permission Verification
     ↓
Access Granted / Denied
     ↓
Security Event Logged
     ↓
Monitoring & Analytics
     ↓
Anomaly Detection
```

---

# 📂 Project Structure

```text
ZeroTrustAPI/
│
├── database/
├── logs/
├── static/
├── templates/
│
├── admin.py
├── analytics.py
├── anomaly_detection.html
├── anomaly_detector.py
├── audit.py
├── auth.py
├── create_admin.py
├── database.py
├── gateway.py
├── main.py
├── requirements.txt
└── README.md
```

> `__pycache__/` and Python `.pyc` files are generated automatically and do not need to be included in the repository.

---

# 📚 Main Project Modules

## `main.py`

The main entry point of the FastAPI application.

It connects the application's different components and starts the main application.

---

## `gateway.py`

Contains the core **Zero Trust Gateway** functionality.

It handles security-related gateway operations and protected service access.

---

## `auth.py`

Handles authentication and security functionality such as:

* User authentication
* Password handling
* JWT-related authentication
* Security verification

---

## `admin.py`

Contains functionality related to administrator operations and administrative access.

---

## `create_admin.py`

Used for creating or initializing an administrator account.

---

## `audit.py`

Handles security audit logging and records important application/security events.

---

## `analytics.py`

Provides functionality related to API activity and security analytics.

---

## `anomaly_detector.py`

Contains the machine learning-based anomaly detection functionality used to identify unusual activity.

---

## `database.py`

Handles the database configuration and communication between the application and the SQLite database using SQLAlchemy.

---

## `templates/`

Contains the **Jinja2 HTML templates** used for the application's frontend pages.

---

## `static/`

Contains static frontend resources such as CSS and other assets.

---

## `logs/`

Contains application/security log information generated by the system.

---

## `database/`

Contains database-related application data.

---

# 🛠️ Technologies Used

| Technology   | Purpose                            |
| ------------ | ---------------------------------- |
| Python       | Core programming language          |
| FastAPI      | Backend and API development        |
| Uvicorn      | ASGI server for running FastAPI    |
| SQLAlchemy   | Database ORM                       |
| SQLite       | Application database               |
| JWT          | Token-based authentication         |
| Passlib      | Password security                  |
| PBKDF2       | Secure password hashing            |
| Jinja2       | Dynamic HTML templates             |
| HTML         | Frontend structure                 |
| CSS          | Frontend styling                   |
| Scikit-learn | Machine learning anomaly detection |
| NumPy        | Numerical processing               |
| Pandas       | Data processing and analysis       |

---

# 📦 Dependencies

Install the required dependencies using:

```bash
pip install fastapi uvicorn sqlalchemy jinja2 python-multipart passlib pyjwt scikit-learn numpy pandas
```

Alternatively, if `requirements.txt` is included:

```bash
pip install -r requirements.txt
```

### `requirements.txt`

```text
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

---

# ▶️ Run the Application

Start the FastAPI application using Uvicorn:

```bash
python -m uvicorn main:app --reload
```

After the server starts, open the application at:

```text
http://127.0.0.1:8000
```

---

# 🔐 Demo Admin Login

For testing the administrative functionality of the project, the local demonstration account is:

```text
Username: admin01
Password: Admin@123
```

The administrator account can be used to access administrative functionality such as user management, service management, security monitoring, and audit information.

> ⚠️ **Security Note:** These credentials are intended only for local demonstration/testing. Hard-coded credentials should never be used in a production environment.

---

# 📖 FastAPI API Documentation

FastAPI provides interactive Swagger API documentation.

After running the application, it can be accessed at:

```text
http://127.0.0.1:8000/docs
```

The Swagger interface can be used to inspect and test available API endpoints.

---

# 🔐 Security Features

The project demonstrates multiple security mechanisms:

* Zero Trust access verification
* JWT authentication
* PBKDF2 password hashing
* Role-Based Access Control
* Admin and User privileges
* Protected services
* Strong password policy
* Security audit logging
* API monitoring
* Security analytics
* Access control
* Machine learning-based anomaly detection

---

# 🎯 Project Objective

The main objective of this project is to demonstrate how **Zero Trust principles can be applied to API-based applications**.

Instead of relying only on traditional username and password authentication, the system combines:

```text
Authentication
      +
Authorization
      +
Role-Based Access Control
      +
Zero Trust Verification
      +
Audit Logging
      +
API Monitoring
      +
Security Analytics
      +
Anomaly Detection
```

This provides multiple layers of security for accessing protected services.

---

# 🚀 Future Enhancements

The project can be further extended with:

* Multi-Factor Authentication (MFA)
* OTP verification
* OAuth2 integration
* Refresh tokens
* JWT token revocation
* API rate limiting
* HTTPS/TLS
* API key management
* Real-time security alerts
* Advanced anomaly detection
* SIEM integration
* Docker deployment
* Cloud deployment
* Redis caching
* Prometheus monitoring
* Grafana dashboards
* Microservice integration

---

# 📚 Learning Outcomes

This project demonstrates practical understanding of:

* Zero Trust Architecture
* API Security
* Secure Authentication
* Authorization
* JWT Authentication
* Role-Based Access Control
* Password Security
* FastAPI Development
* SQLAlchemy
* Database Management
* Security Audit Logging
* API Monitoring
* Security Analytics
* Machine Learning for Cybersecurity

---

# 👩‍💻 Author

**Aditi Bajpai**

B.Tech – Computer Science and Engineering
Cyber Security
