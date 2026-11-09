# Zero Trust API Gateway – Modular Architecture for Secure API Access

A security-focused **Zero Trust API Gateway using a modular-oriented architecture**, developed using **Python, FastAPI, SQLAlchemy, SQLite, HTML, CSS, Jinja2, JWT Authentication, and Scikit-learn**.

The project follows the Zero Trust security principle:

> **Never Trust, Always Verify**

Instead of automatically trusting a user after login, the system verifies authentication, authorization, roles, and permissions before allowing access to protected services.

The application provides security audit logging, API monitoring, administrative controls, analytics, and machine learning-based anomaly detection.

The project also incorporates **email OTP verification through Gmail SMTP, IP management, API rate limiting, risk scoring, and model performance evaluation**.

Its major responsibilities are organized into separate service components for authentication, gateway access control, administration, audit logging, API monitoring, and anomaly detection. These components work together through the FastAPI application.

---

## 📌 Project Overview

Modern applications rely heavily on APIs for communication between users, applications, databases, and backend services. Improperly protected APIs can expose sensitive resources to unauthorized users.

The **Zero Trust API Gateway using modular-oriented components** acts as a centralized security layer between users and protected services.

When a user attempts to access a protected resource, the gateway performs security checks before deciding whether the request should be allowed or denied.

The gateway provides:

- Secure user authentication
- JWT token verification
- Role-Based Access Control (RBAC)
- Zero Trust access verification
- Protected API services
- Modular service components
- Administrative controls
- Security audit logging
- API activity monitoring
- Security analytics
- Machine learning-based anomaly detection
- Email OTP verification
- OTP expiration and verification attempt limits
- OTP resend cooldown
- API rate limiting
- IP blocking and unblocking
- Risk scoring and severity classification
- Isolation Forest model evaluation
- CSV audit log export

---

# ✨ Key Features

## 🔑 Secure Authentication

The application provides secure registration and login functionality.

Features include:

- User registration
- Secure login
- JWT-based authentication
- Username validation
- Strong password requirements
- Real-time password strength indicator
- Secure password hashing using PBKDF2
- Email-based OTP verification
- OTP expiration and verification attempt limits
- OTP resend cooldown

After successful login and verification, authentication information is used to verify access to protected resources.

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

- User management
- Service management
- Administrative services
- Security audit log access
- API monitoring
- Security analytics
- IP management

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
IP and Rate-Limit Checks
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

The **API Gateway** acts as the central security checkpoint for protected services and coordinates the modular security components.

The frontend communicates with the FastAPI backend through application routes/endpoints.

Before protected functionality is accessed, the gateway can perform checks such as:

- Is the user authenticated?
- Is the authentication information valid?
- What role does the user have?
- Does the user have permission to access this service?
- Is the request coming from a blocked IP address?
- Has the user exceeded the configured request limit?
- Should the request be allowed or denied?
- Should the activity be recorded for security monitoring?

This creates a centralized security layer for application access.

Additional request checks include configured rate-limiting rules and blocked-IP checks. Relevant request activity is collected for monitoring and security analysis.

---

# 🌐 Protected Services

The application is organized around multiple service responsibilities/components, including:

### Gateway Service

Handles gateway-related operations and access verification.

### Authentication Service

Provides user registration, login, password verification, JWT-related authentication, and email OTP verification.

### User Service

Provides protected functionality for authenticated and authorized users.

### Admin Service

Provides restricted functionality that can only be accessed by administrators.

### Audit Logging Service

Records important security events and administrative actions.

### API Monitoring Service

Collects and displays API activity and request statistics.

### Anomaly Detection Service

Analyses collected activity statistics to identify potentially unusual patterns.

---

# 👨‍💻 Admin User Management

Administrators can manage users from the administrative interface.

Supported operations include:

- Create users
- View users
- Update user information
- Delete users
- Manage user roles

This provides centralized control over application users.

---

# ⚙️ Service Management

The administrator can manage services protected by the Zero Trust Gateway.

Service management provides control over protected resources and their associated security settings.

---

# 📋 Security Audit Logging

The application records important security-related events.

Examples include:

- Successful login attempts
- Failed login attempts
- Gateway access
- Protected service access
- Access denied events
- Administrative actions
- User management actions
- System events

Audit logging provides a record of important activity occurring within the application.

---

# 📊 API Monitoring & Analytics

The application includes monitoring and analytics functionality for observing API and gateway activity.

Information can include:

- API request statistics
- Gateway health
- Service status
- Endpoint usage
- Recent API activity
- Security events
- User activity
- Allowed requests
- Denied requests
- Rate-limited requests

This allows administrators to understand how protected services are being accessed.

---

# 🤖 Machine Learning-Based Anomaly Detection

The project integrates **Scikit-learn** for anomaly detection.

The anomaly detection component analyses application activity to identify potentially unusual access patterns.

Examples of activity that may be identified as unusual include:

- Excessive request activity
- Abnormal API usage
- Unexpected user behavior
- Unusual access patterns

Suspicious activity can then be highlighted for further security investigation.

### Anomaly Detection Features

The Isolation Forest model analyses collected API activity statistics using features such as:

- Total API requests
- Denied requests
- Failed login attempts
- Rate-limited requests
- Unique endpoints accessed

The model uses StandardScaler for feature scaling and is configured with:

- `n_estimators=150`
- `contamination="auto"`
- `max_samples="auto"`
- `random_state=42`

The live anomaly detection functionality analyses collected activity statistics. An anomaly indicates unusual activity and does not automatically confirm a malicious attack.

### Risk Scoring

The project also incorporates risk assessment using rule-based checks and machine learning predictions.

The risk score ranges from **0 to 100** and classifies activity into severity levels:

- Low
- Medium
- High
- Critical

This provides administrators with additional information to investigate potentially suspicious activity.

### Model Performance Evaluation

The project includes model performance evaluation using a separate synthetic labelled dataset.

The evaluation functionality provides:

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- ROC-AUC
- Confusion Matrix
- ROC Curve
- Precision-Recall Curve

The evaluation dataset is separate from live application traffic. Its results should not be interpreted as real-world validation.

---

# 🌍 IP Management

The application provides IP management functionality for administrators.

Administrators can:

- View IP management information
- Block IP addresses
- Unblock IP addresses
- Restrict requests from blocked IP addresses

The gateway checks the blocked-IP information as part of request security verification.

Loopback IP addresses are protected from accidental blocking.

---

# 🚦 API Rate Limiting

The application includes rate-limiting functionality to restrict excessive API requests.

Rate limiting helps control request activity and reduces the possibility of excessive or abusive API usage.

Requests that exceed configured limits can be restricted and recorded for monitoring.

---

# 📁 CSV Audit Log Export

Security audit logs can be exported in **CSV format**.

Exported logs can be used for:

- Security analysis
- Reporting
- Documentation
- Compliance-related activities
- Incident investigation

---

# 🏗️ System Architecture – Microservices-Oriented Design

The project follows a **microservices-oriented architecture** by separating major security responsibilities into dedicated service components.

The API Gateway acts as the central entry point for protected requests and coordinates the security checks before access is granted.

### Main Service Components

**1. Authentication Service**

Responsible for:

- User registration
- Login
- Password hashing and verification
- JWT-related authentication
- Email OTP verification

**2. API Gateway Service**

Responsible for:

- Receiving application requests
- Authentication verification
- Authorization checks
- Role and permission verification
- Access decisions
- Coordination of protected service access

**3. User and Admin Service**

Responsible for:

- User management
- Administrator operations
- Role management
- Service management

**4. Audit Logging Service**

Responsible for:

- Recording security events
- Recording access decisions
- Recording administrative actions
- Maintaining audit information

**5. API Monitoring and Analytics Service**

Responsible for:

- API request monitoring
- Request statistics
- Endpoint activity
- Allowed and denied request tracking
- Rate-limited request tracking
- Dashboard analytics

**6. Anomaly Detection Service**

Responsible for:

- Analysing API activity statistics
- Isolation Forest anomaly detection
- Identifying unusual activity
- Supporting risk assessment
- Model performance evaluation

**7. IP Management and Rate-Limiting Components**

Responsible for:

- IP blocking and unblocking
- Blocked-IP verification
- Request rate control
- Restricting excessive API requests

These components are logically separated into dedicated Python modules and application routes within the current FastAPI application. They represent separate service responsibilities, but are not claimed to be independently deployed processes with separate ports or network communication.

### Architecture Diagram

```text
                  User / Administrator
                          |
                          v
                  HTML / CSS Frontend
                          |
                          v
                    Jinja2 Templates
                          |
                          v
                    FastAPI Backend
                          |
                          v
                 ZERO TRUST API GATEWAY
                          |
        +-----------------+------------------+
        |                 |                  |
        v                 v                  v
 Authentication      User / Admin       Rate Limiting
    Service             Service             Service
        |                 |                  |
        v                 v                  v
   Email OTP          RBAC Checks         IP Checks
        |                 |                  |
        +-----------------+------------------+
                          |
                          v
                    Access Decision
                     /          \
                    /            \
                 ALLOW          DENY
                   |              |
                   v              v
             Protected       Access Denied
              Services
                   |
                   v
          Audit Logging Service
                   |
                   v
        API Monitoring & Analytics
                   |
                   v
          Anomaly Detection Service
                   |
                   v
              Risk Scoring
                   |
                   v
             Security Dashboard
                   |
                   v
              SQLAlchemy ORM
                   |
                   v
                 SQLite
```

### Additional Security and Analytics Flow

```text
API Request Activity
        |
        v
API Monitoring and Analytics
        |
        v
Collected Activity Statistics
        |
        v
StandardScaler
        |
        v
Isolation Forest
        |
        v
Anomaly Prediction
        |
        v
Rule-Based Checks + ML Prediction
        |
        v
Risk Score (0–100)
        |
        v
Low / Medium / High / Critical
        |
        v
Security Dashboard
```

---

# 🔄 Application Workflow

```text
Registration
     |
     v
Input Validation
     |
     v
Password Hashing
     |
     v
Database Storage
     |
     v
Login
     |
     v
Credential Verification
     |
     v
Email OTP Verification
     |
     v
JWT Authentication
     |
     v
Protected Request
     |
     v
Zero Trust API Gateway
     |
     v
Authentication Verification
     |
     v
IP and Rate-Limit Checks
     |
     v
Role / Permission Verification
     |
     v
Access Granted / Denied
     |
     v
Security Event Logged
     |
     v
Monitoring & Analytics
     |
     v
Anomaly Detection
     |
     v
Risk Assessment
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
├── email_service.py
├── gateway.py
├── main.py
├── rate_limiter.py
├── requirements.txt
└── README.md
```

> `__pycache__/` and Python `.pyc` files are generated automatically and do not need to be included in the repository.

---

# 📚 Main Project Modules

## `main.py`

The main entry point of the FastAPI application.

It connects the application's different components and starts the main application.

## `gateway.py`

Contains the core **Zero Trust Gateway** functionality.

It handles security-related gateway operations and protected service access.

## `auth.py`

Handles authentication and security functionality such as:

- User authentication
- Password handling
- JWT-related authentication
- Security verification
- Email OTP verification flow

## `admin.py`

Contains functionality related to administrator operations and administrative access.

## `create_admin.py`

Used for creating or initializing an administrator account.

## `audit.py`

Handles security audit logging and records important application/security events.

## `analytics.py`

Provides functionality related to API activity and security analytics.

## `anomaly_detector.py`

Contains the machine learning-based anomaly detection functionality used to identify unusual activity.

## `database.py`

Handles the database configuration and communication between the application and the SQLite database using SQLAlchemy.

## `email_service.py`

Handles email-related functionality used by the application, including delivery of OTP verification emails through Gmail SMTP.

## `rate_limiter.py`

Contains rate-limiting functionality used to restrict excessive API requests.

## `templates/`

Contains the **Jinja2 HTML templates** used for the application's frontend pages.

## `static/`

Contains static frontend resources such as CSS and other assets.


## `database/`

Contains database-related application data.

---

# 🛠️ Technologies Used

| Technology     | Purpose                               |
| -------------- | ------------------------------------- |
| Python         | Core programming language             |
| FastAPI        | Backend and API development           |
| Uvicorn        | ASGI server for running FastAPI       |
| SQLAlchemy     | Database ORM                          |
| SQLite         | Application database                  |
| JWT            | Token-based authentication            |
| Passlib        | Password security                     |
| PBKDF2         | Secure password hashing               |
| Jinja2         | Dynamic HTML templates                |
| HTML           | Frontend structure                    |
| CSS            | Frontend styling                      |
| Scikit-learn   | Machine learning anomaly detection    |
| NumPy          | Numerical processing                  |
| Pandas         | Data processing and analysis          |
| Chart.js       | Dashboard data visualization          |
| Gmail SMTP     | Email OTP delivery                    |
| StandardScaler | Feature scaling for anomaly detection |

---

# 📦 Dependencies

Install the required dependencies using:

```cmd
pip install fastapi uvicorn sqlalchemy jinja2 python-multipart passlib pyjwt scikit-learn numpy pandas python-dotenv
```

Alternatively, if `requirements.txt` is included:

```cmd
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
python-dotenv
```

---

# ▶️ Run the Application

## 💻 Development Environment

The project was developed using **Windows Command Prompt (CMD) and Windows Notepad**. Python files and other project files were created and edited using Notepad, while commands were executed through CMD.

Visual Studio Code is not required to run this project.

### Open the Project Using CMD

Open Command Prompt and navigate to the project folder. For example:

```cmd
cd %USERPROFILE%\ZeroTrustAPI
```

If the project is stored in another location, use that folder's actual path.

### Open or Edit a Project File Using Notepad

For example, to open the main application file:

```cmd
notepad main.py
```

To open another Python file:

```cmd
notepad gateway.py
notepad auth.py
notepad anomaly_detector.py
```

Save changes in Notepad before running the application.

### Create and Activate a Virtual Environment

Run these commands in CMD from the project folder:

```cmd
python -m venv venv
venv\Scripts\activate
```

### Install Project Dependencies

```cmd
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the dependencies listed in the Dependencies section.

### Configure Environment Variables

Create or edit the `.env` file using Notepad:

```cmd
notepad .env
```

Add the environment variables required by the application.

For example, if these names match the variables used in the code:

```env
SECRET_KEY=replace_with_a_secure_secret
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_google_app_password
```

Use the exact variable names expected by the application. Do not upload the real `.env` file or credentials to GitHub.

---

# 📧 Gmail SMTP Configuration for Email OTP Verification

The application uses **Gmail SMTP (Simple Mail Transfer Protocol)** to send one-time passwords (OTPs) to users during email verification.

SMTP is the protocol that allows the application to send verification emails through Gmail.

The `email_service.py` module handles the email delivery functionality.

## Step 1: Choose a Gmail Account

Choose the Gmail account that you want the application to use for sending OTP verification emails.

For example:

```text
your_email@gmail.com
```

This will be the sender email account.

## Step 2: Enable 2-Step Verification in Google

Google requires 2-Step Verification before generating an App Password.

1. Sign in to the Google Account that will send the OTP emails.
2. Open your Google Account settings.
3. Navigate to the **Security** section.
4. Find **2-Step Verification**.
5. Enable it by following Google's verification instructions.

After enabling 2-Step Verification, you can check whether the App Password option is available.

## Step 3: Generate a Google App Password

An App Password is a separate password generated by Google that allows an application to authenticate with your Gmail account.

Follow these steps:

1. Open your Google Account settings.
2. Navigate to the Security section.
3. Search for **App passwords**.
4. Open the App Passwords option.
5. Google may ask you to sign in again.
6. Enter an application name such as:

```text
ZeroTrustAPI
```

7. Generate the App Password.
8. Google will display a 16-character password.
9. Copy this password and store it securely.

**Important:** Do not use your normal Gmail account password in the project. Use the Google-generated App Password.

App Passwords may not be available for some account configurations, including certain managed accounts and accounts using Advanced Protection.

## Step 4: Configure Gmail SMTP Settings

The standard Gmail SMTP configuration using STARTTLS is:

| Setting       | Value                   |
| ------------- | ----------------------- |
| SMTP Server   | `smtp.gmail.com`        |
| SMTP Port     | `587`                   |
| Encryption    | STARTTLS                |
| SMTP Username | Your full Gmail address |
| SMTP Password | Google App Password     |

These settings allow the Python application to connect to Gmail's SMTP server and send emails.

## Step 5: Configure the `.env` File

Open your project's root directory.

Create or edit the `.env` file:

```cmd
notepad .env
```

Add the Gmail credentials:

```env
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_16_character_google_app_password
```

Example with placeholder values:

```env
SMTP_EMAIL=example@gmail.com
SMTP_PASSWORD=abcd1234efgh5678
```

Replace the example values with your own Gmail address and generated App Password.

**Important:** These environment variable names are examples. Open `email_service.py` and check which exact variable names your code reads. The names in `.env` must match the names expected by the Python code.

For example, if your code reads `SMTP_USER` and `EMAIL_PASSWORD`, use those names instead.

## Step 6: Connect Gmail SMTP Through `email_service.py`

The `email_service.py` module is responsible for sending OTP verification emails.

The general email integration process is:

```text
User Registration / Login
          |
          v
OTP Generation
          |
          v
Email Service
          |
          v
Read Gmail Credentials
          |
          v
Connect to Gmail SMTP
          |
          v
SMTP Authentication
          |
          v
Send OTP Email
          |
          v
User Receives OTP
          |
          v
OTP Verification
```

The email service needs to:

1. Read the Gmail address from the environment variables.
2. Read the Google App Password from the environment variables.
3. Connect to `smtp.gmail.com`.
4. Use port `587` for STARTTLS if configured that way in the code.
5. Authenticate using the Gmail address and App Password.
6. Create the OTP email.
7. Send the email to the user's registered email address.

The standard Python SMTP connection flow using STARTTLS looks like this:

```python
import smtplib
import ssl

smtp_server = "smtp.gmail.com"
smtp_port = 587

context = ssl.create_default_context()

with smtplib.SMTP(smtp_server, smtp_port) as server:
    server.starttls(context=context)
    server.login(sender_email, app_password)
    server.send_message(message)
```

This is an illustrative SMTP connection flow. Keep the actual implementation in your `email_service.py` consistent with the environment variable names and email functions already used by your application.

## Step 7: Configure OTP Verification

The email service sends the generated OTP to the user's registered email address.

The verification process works as follows:

1. The user enters their registered email address.
2. The application generates a one-time password.
3. The email service sends the OTP through Gmail SMTP.
4. The user receives the OTP in their inbox.
5. The user enters the OTP in the application.
6. The application checks whether the OTP is valid.
7. If the OTP is correct and has not expired, verification succeeds.

The project's OTP flow includes:

- 6-digit OTP
- 5-minute OTP expiration
- Maximum 3 incorrect verification attempts
- 60-second OTP resend cooldown

## Step 8: Test Gmail OTP Delivery

After configuring Gmail:

1. Save the `.env` file.
2. Activate the virtual environment.
3. Start the FastAPI application.
4. Open the application in your browser.
5. Register or log in using an email address you can access.
6. Check your inbox for the OTP verification email.
7. If the email is not visible, check the Spam/Junk folder.
8. Enter the OTP before it expires.

If the OTP email is received successfully, Gmail SMTP integration is working.

## Step 9: Protect Gmail Credentials

Security precautions:

- Never upload `.env` to GitHub.
- Never expose your Google App Password.
- Do not hard-code Gmail credentials in Python files.
- Do not include real credentials in screenshots or documentation.
- Use placeholder credentials in `.env.example`.
- Revoke and regenerate an App Password if it is exposed.

Add the following entries to `.gitignore`:

```gitignore
.env
venv/
__pycache__/
*.pyc
```

### Troubleshooting Gmail SMTP

If OTP emails are not being delivered, check:

- Whether 2-Step Verification is enabled.
- Whether the Google App Password is correct.
- Whether the `.env` file is in the project root.
- Whether the environment variable names match `email_service.py`.
- Whether the SMTP server is `smtp.gmail.com`.
- Whether the SMTP port and encryption method match the code.
- Whether the application is loading environment variables correctly.
- Whether the recipient email address is correct.

**Note:** Gmail SMTP configuration is required for the email OTP functionality to send verification emails successfully.

---

# 🚀 Start the FastAPI Application

After configuring the dependencies and environment variables, start the application using Uvicorn:

```cmd
python -m uvicorn main:app --reload
```

After the server starts, open the application at:

```text
http://127.0.0.1:8000
```

If CMD reports that a required Python package is missing, activate the virtual environment and run:

```cmd
pip install -r requirements.txt
```

Keep the CMD window open while using the application.

To stop the local development server, press:

```text
CTRL + C
```

---

# 💻 Running the Project Using Visual Studio Code (2nd Way)

The project can also be opened and run using Visual Studio Code.

This is an alternative way to execute the application. The project was originally developed using Windows Notepad and Command Prompt (CMD).

### Step 1: Install Visual Studio Code

1. Download and install Visual Studio Code.
2. Open Visual Studio Code.
3. Open the Extensions Marketplace.
4. Install the Python extension.

### Step 2: Open the Project Folder

1. Open Visual Studio Code.
2. Select **File → Open Folder**.
3. Select the `ZeroTrustAPI` project folder.
4. The project files and folders will appear in the Explorer panel.

### Step 3: Open the Integrated Terminal

1. Select **Terminal → New Terminal**.
2. Make sure the terminal is opened inside the `ZeroTrustAPI` project directory.

### Step 4: Create a Virtual Environment

```cmd
python -m venv venv
```

### Step 5: Activate the Virtual Environment

For Windows:

```cmd
venv\Scripts\activate
```

### Step 6: Install Project Dependencies

```cmd
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 7: Configure Gmail OTP Verification

1. Open the `.env` file in the project directory.
2. If it does not exist, create it in the project root.
3. Add the Gmail address and Google App Password.
4. Make sure the variable names match those used in `email_service.py`.
5. Save the file.

Refer to the **Gmail SMTP Configuration for Email OTP Verification** section for the complete Google App Password setup instructions.

### Step 8: Run the Application

Execute:

```cmd
python -m uvicorn main:app --reload
```

### Step 9: Access the Application

Open a browser and navigate to:

- **Application:** `http://127.0.0.1:8000`
- **FastAPI Documentation:** `http://127.0.0.1:8000/docs`

### Step 10: Stop the Application

To stop the development server, click inside the VS Code terminal and press:

```text
CTRL + C
```

---

# 🔐 Demo Admin Login

For testing the administrative functionality of the project, the local demonstration account is:

```text
Username: admin01
Password: Admin@123
```

The administrator account can be used to access administrative functionality such as:

- User management
- Service management
- Security monitoring
- Audit information
- IP management


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

- Zero Trust access verification
- JWT authentication
- PBKDF2 password hashing
- Role-Based Access Control
- Admin and User privileges
- Protected services
- Strong password policy
- Email OTP verification
- Security audit logging
- API monitoring
- Security analytics
- IP blocking and unblocking
- API rate limiting
- Machine learning-based anomaly detection
- Risk scoring
- Model performance evaluation

---

# 🎯 Project Objective

The main objective of this project is to demonstrate how **Zero Trust principles can be applied to API-based applications using a microservices-oriented architecture**.

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
Email OTP Verification
      +
IP Management
      +
API Rate Limiting
      +
Audit Logging
      +
API Monitoring
      +
Security Analytics
      +
Anomaly Detection
      +
Risk Assessment
```

This provides multiple layers of security for accessing protected services.

---

# 🚀 Future Enhancements

The project can be further extended with:

- Independently deployable microservices
- Inter-service communication
- API service discovery
- OAuth2 integration
- Refresh tokens
- JWT token revocation
- Advanced API rate limiting
- HTTPS/TLS
- API key management
- Real-time security alerts
- Advanced anomaly detection
- SIEM integration
- Docker deployment
- Cloud deployment
- Redis caching
- Prometheus monitoring
- Grafana dashboards

---

# 📚 Learning Outcomes

This project demonstrates practical understanding of:

- Zero Trust Architecture
- Microservices-oriented system design
- API Security
- Secure Authentication
- Authorization
- JWT Authentication
- Role-Based Access Control
- Password Security
- Email OTP Integration
- Gmail SMTP Configuration
- FastAPI Development
- SQLAlchemy
- Database Management
- Security Audit Logging
- API Monitoring
- Security Analytics
- IP Management
- API Rate Limiting
- Machine Learning for Cybersecurity
- Isolation Forest anomaly detection
- Model performance evaluation
- API risk assessment

---
# 👩‍💻 Author

**Aditi Bajpai**

B.Tech – Computer Science and Engineering (Cyber Security) minor in Software System Design
