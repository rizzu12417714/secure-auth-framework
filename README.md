# SECURE USER AUTHENTICATION AND VAULT SYSTEM
## Comprehensive Project Report

---

## 1. PROJECT OVERVIEW

The **Secure User Authentication and Vault System** is a comprehensive desktop application designed to provide a robust, multi-layered security authentication mechanism. This project implements industry-standard security practices including password hashing, two-factor authentication (2FA) via OTP, account lockout mechanisms, and detailed audit logging.

### Key Objectives:
- Provide a secure user authentication system with modern security standards
- Implement multi-factor authentication (MFA) using One-Time Passwords (OTP)
- Maintain detailed audit logs for security event tracking
- Prevent brute-force attacks through account lockout mechanisms
- Support role-based access control (Admin/User roles)
- Provide a user-friendly GUI for authentication workflows

### Project Scope:
- User registration with validation
- Secure login with password hashing
- OTP-based email verification (2FA)
- Social login integration (Google, GitHub, Facebook)
- User management interface (Admin only)
- Access logs and audit trails
- Account lockout after failed attempts

---

## 2. MODULE-WISE BREAKDOWN

### Module 1: Database Management (`init_db()`)
**Purpose:** Initialize and manage SQLite database structure
- Creates `users` table with secure schema
- Creates `audit_logs` table for event tracking
- Handles database schema compatibility
- Manages database connections

**Key Tables:**
| Table Name | Columns |
|-----------|---------|
| users | id, username, password_hash, email, role, failed_attempts, locked_until, mfa_secret, salt |
| audit_logs | id, username, event, timestamp |

---

### Module 2: SMTP Email & OTP Management
**Purpose:** Handle email verification and OTP generation
- `send_otp()` - Generates 6-digit OTP and sends via SMTP
- `load_smtp_credentials()` - Loads email configuration
- Supports environment variables and default credentials
- Uses Gmail SMTP server (smtp.gmail.com:587) with TLS encryption

**Features:**
- Random 6-digit OTP generation (100000-999999)
- 2-minute validity period (120 seconds)
- Configurable SMTP credentials
- Email delivery error handling

---

### Module 3: Input Validation & Security
**Purpose:** Validate and sanitize user inputs
- `validate_username()` - Allows 3-32 characters (letters, numbers, _, -)
- `validate_email()` - RFC 5322 compliant email validation
- `validate_password()` - Enforces strong password requirements
- `mask_email()` - Protects email privacy in UI

**Password Requirements:**
- Minimum length: 1 character (but must include diversity)
- Must contain: uppercase, lowercase, digit, special character
- Example: `SecurePass@123`

---

### Module 4: Authentication Logic
**Purpose:** Handle user registration and login workflows
- `handle_register()` - New user account creation
- `handle_login()` - User credential verification
- `issue_otp_for_email()` - 2FA challenge initiation
- `verify_otp_logic()` - OTP code validation
- `resend_otp_logic()` - OTP resend with rate limiting

**Key Features:**
- Bcrypt password hashing with SHA-256 pre-hashing
- Account lockout: 5 failed attempts = 15-minute lockout
- OTP attempt limit: 3 attempts before restart
- OTP resend limit: 3 resends with 30-second cooldown
- Social login support (Google, GitHub, Facebook)

---

### Module 5: Access Control & Role Management
**Purpose:** Implement role-based access control
- Two roles: `admin`, `user`
- Admin access to user management and audit logs
- `open_user_management()` - Admin user list viewer
- `open_access_logs()` - Admin audit log viewer

---

### Module 6: Audit Logging
**Purpose:** Track all security-related events
- `log_event()` - Record event to database
- Tracks: registration, login, failed attempts, OTP challenges, logouts

**Tracked Events:**
- User registration successful/failed
- Login attempts (success/failure)
- OTP challenges issued/failed/expired
- Account lockouts
- Unauthorized access attempts
- User logout

---

### Module 7: GUI Interface (Tkinter)
**Purpose:** Provide user-friendly authentication interface
- `login_frame` - Login credentials entry
- `register_frame` - New account registration
- `otp_frame` - OTP verification screen
- `dashboard_frame` - Post-login dashboard
- `show_frame()` - Frame navigation logic
- `refresh_dashboard_view()` - Dashboard data refresh

---

## 3. FUNCTIONALITIES

### Core Functionalities:

#### 3.1 User Registration
- Input validation (username, email, password)
- Password strength enforcement
- Duplicate username prevention
- Account creation with hashed password
- Event logging

#### 3.2 User Login
- Credential verification
- Account lockout after 5 failed attempts
- 15-minute lockout period
- OTP challenge if email on file
- Session initialization

#### 3.3 Two-Factor Authentication (2FA)
- OTP generation and email delivery
- 2-minute OTP validity
- 3 verification attempts
- OTP resend capability (max 3 times)
- 30-second resend cooldown

#### 3.4 Social Login
- Provider-based login (Google, GitHub, Facebook)
- Email-based verification
- Automatic OTP challenge
- Social account integration

#### 3.5 User Management (Admin)
- View all registered users
- Display user roles and IDs
- User list in dedicated interface

#### 3.6 Audit Logging
- Track all security events
- View latest 100 security events
- Timestamps for each event
- Admin-only access

#### 3.7 Account Security
- Password reset capability
- Failed attempt tracking
- Account lockout mechanism
- Email verification
- Session management

---

## 4. TECHNOLOGY USED

### 4.1 Programming Languages:
- **Python** (v3.6+) - Primary language for application logic

### 4.2 Libraries and Tools:

| Library | Version | Purpose |
|---------|---------|---------|
| tkinter | Built-in | GUI framework for desktop interface |
| sqlite3 | Built-in | Lightweight database management |
| bcrypt | Latest | Password hashing and verification |
| smtplib | Built-in | SMTP protocol for email delivery |
| hashlib | Built-in | SHA-256 password pre-hashing |
| re | Built-in | Input validation with regex |
| datetime | Built-in | Timestamp and expiry management |
| os | Built-in | Environment variables and file paths |

### 4.3 Other Tools:
- **SQLite** - Database (secure_vault.db)
- **Gmail SMTP** - Email delivery service (smtp.gmail.com:587)
- **Git/GitHub** - Version control (if used)

### 4.4 Security Standards:
- **Bcrypt** - Industry-standard password hashing
- **SHA-256** - Pre-hashing for password normalization
- **TLS/SSL** - Encrypted SMTP connection
- **OWASP** - Security best practices compliance

---

## 5. FLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION START                            │
│                                                                 │
│  1. Initialize SQLite Database                                 │
│  2. Load SMTP Configuration                                    │
│  3. Display Login Frame (Tkinter GUI)                          │
└────────────┬────────────────────────────────────────────────────┘
             │
             ├─────────────────────────────────────────────────────┐
             │                                                     │
        ┌────▼─────┐                                      ┌────────▼──┐
        │  LOGIN   │                                      │ REGISTER │
        └────┬─────┘                                      └────────┬──┘
             │                                                     │
             ├─ Check credentials                                 ├─ Validate inputs
             ├─ Hash password (SHA256 + Bcrypt)                   ├─ Check duplicate username
             ├─ Check failed attempts                             ├─ Insert into users table
             ├─ Check account lockout                             ├─ Log event
             │                                                     └─ Show login frame
             ├─ Success: User email available?
             │
             ├──[YES]─ Generate OTP ──────────────────┐
             │         │                                │
             │         ├─ Send OTP via SMTP            │
             │         ├─ Set 2-min expiry            │
             │         ├─ Show OTP Frame               │
             │         │                                │
             │         ├─ User enters OTP              │
             │         │                                │
             │         ├─ Validate OTP                 │
             │         │                                │
             │         ├─[VALID]──────────────────────┤
             │         │                                │
             │         └─[INVALID]─ Check attempts     │
             │                      │                  │
             │                      ├─[Max]─ Logout   │
             │                      └─[<Max]─ Retry   │
             │                                         │
             ├──[NO]─ Skip OTP ─────────────────────┐
             │                                       │
             ├─[FAILED] ─ Increment failed attempts │
             │            ├─ Log event              │
             │            └─ Check lockout          │
             │                                       │
             └─────────────────────────────────────┤
                                                  │
                                         ┌────────▼─────────┐
                                         │  DASHBOARD/MAIN  │
                                         │    (Logged In)   │
                                         │                  │
                                         ├─ Show Username   │
                                         ├─ Show Role       │
                                         ├─ [Admin] Features│
                                         │  ├─ User Mgmt    │
                                         │  └─ Audit Logs   │
                                         ├─ [User] Features │
                                         │  └─ View Profile │
                                         ├─ Logout Button   │
                                         │  │               │
                                         │  └─ Clear session│
                                         └─────────────────┘
```

---

## 6. REVISION TRACKING ON GITHUB

### Repository Information:
- **Repository Name:** `Secure-User-Authentication-Vault`
- **Project Type:** Desktop Application - Security/Authentication
- **Visibility:** Private/Public (as per requirements)

### GitHub Setup Structure:
```
.gitignore
├── *.db
├── smtp_config.json
├── __pycache__/
└── *.pyc

README.md
├── Project overview
├── Installation guide
├── Usage instructions
├── Security warnings

secuare.py
├── Main application file
├── All authentication logic
└── GUI implementation

smtp_config.json
└── SMTP configuration (template)

user_vault/
└── khanbhai_abcd.py (related utilities)

docs/
├── API_DOCUMENTATION.md
├── SECURITY_POLICY.md
├── INSTALLATION_GUIDE.md
└── USAGE_GUIDE.md

tests/
├── test_authentication.py
├── test_validation.py
└── test_otp.py
```

### GitHub Link Format:
```
https://github.com/[YourUsername]/Secure-User-Authentication-Vault
```

### Recommended Git Workflow:
```bash
# Initialize repository
git init
git add .
git commit -m "Initial commit: Secure authentication system"

# Create branches
git branch develop
git branch feature/mfa-enhancement
git branch bugfix/security-issues

# Commit messages
git commit -m "feat: Add OTP email verification"
git commit -m "fix: Account lockout mechanism"
git commit -m "docs: Update security policy"
```

---

## 7. CONCLUSION AND FUTURE SCOPE

### Project Achievements:
✓ Implemented industry-standard password hashing (Bcrypt + SHA-256)  
✓ Multi-factor authentication with OTP-based verification  
✓ Rate limiting and brute-force protection  
✓ Comprehensive audit logging system  
✓ Role-based access control (Admin/User)  
✓ Email-based social login support  
✓ Tkinter-based user-friendly GUI  
✓ SQLite database with proper schema design  

### Security Features Implemented:
- Account lockout after 5 failed login attempts (15 minutes)
- OTP validity period: 2 minutes
- OTP resend limit: 3 times with 30-second cooldown
- OTP verification attempt limit: 3 attempts
- Email masking in UI (privacy protection)
- Comprehensive audit trails
- Input validation and sanitization

### Future Enhancements & Scope:

#### Phase 2 - Advanced Features:
1. **Biometric Authentication**
   - Fingerprint recognition
   - Facial recognition integration
   - Hardware security keys support

2. **Enhanced MFA Options**
   - SMS-based OTP
   - Authenticator app integration (Google Authenticator)
   - Recovery codes for account access

3. **User Profile Management**
   - Profile picture uploads
   - Personal information management
   - Account recovery options
   - Two-device verification

4. **Advanced Security**
   - Encryption at rest for sensitive data
   - IP-based access restrictions
   - Geolocation-based login alerts
   - Passwordless authentication

5. **Web Interface**
   - Flask/Django-based web version
   - RESTful API development
   - Single Sign-On (SSO) integration
   - OAuth 2.0 implementation

6. **Mobile Application**
   - Cross-platform mobile app (React Native/Flutter)
   - Push notifications for login attempts
   - Mobile OTP delivery

7. **Enterprise Features**
   - LDAP/Active Directory integration
   - Bulk user management
   - Compliance reporting (GDPR, HIPAA)
   - Custom authentication policies

8. **Performance & Scalability**
   - Database migration to PostgreSQL/MySQL
   - Distributed session management
   - Caching layer (Redis)
   - Load balancing setup

9. **DevOps & Deployment**
   - Docker containerization
   - CI/CD pipeline (GitHub Actions)
   - Automated testing
   - Cloud deployment (AWS/Azure/GCP)

10. **Monitoring & Analytics**
    - Real-time dashboard
    - Login analytics
    - Security threat detection
    - Performance monitoring

### Potential Use Cases:
- Enterprise employee authentication system
- Educational institution student portal
- Financial services user access control
- Healthcare patient portal
- E-commerce platform security
- SaaS application authentication

---

## 8. REFERENCES

### Security Standards & Best Practices:
1. **OWASP Top 10** - Web Application Security
   - Link: https://owasp.org/www-project-top-ten/
   
2. **NIST Cybersecurity Framework** - Security Guidelines
   - Link: https://www.nist.gov/cyberframework
   
3. **CWE-352: Cross-Site Request Forgery (CSRF)**
   - Link: https://cwe.mitre.org/data/definitions/352.html
   
4. **RFC 5321** - SMTP Protocol
   - Link: https://tools.ietf.org/html/rfc5321

5. **RFC 5322** - Email Format Standard
   - Link: https://tools.ietf.org/html/rfc5322

### Libraries & Documentation:
1. **Bcrypt Documentation**
   - Link: https://pypi.org/project/bcrypt/
   
2. **Tkinter Official Guide**
   - Link: https://docs.python.org/3/library/tkinter.html
   
3. **SQLite Official Documentation**
   - Link: https://www.sqlite.org/docs.html
   
4. **Python smtplib Module**
   - Link: https://docs.python.org/3/library/smtplib.html

### Security Tools:
1. **OWASP ZAP** - Security Scanner
2. **Burp Suite** - Web Security Testing
3. **Snyk** - Dependency Vulnerability Scanner
4. **SonarQube** - Code Quality & Security

---

## 9. SCREENSHOTS

Below are the screenshots captured during development and while using the application. Click the images to view them at full size.

![Login Screen](screenshots/Screenshot 2026-05-05 221034.png)

![Registration Screen](screenshots/Screenshot 2026-05-05 221059.png)

![OTP Verification Screen](screenshots/Screenshot 2026-05-05 221118.png)

![Dashboard - User View](screenshots/Screenshot 2026-05-05 221136.png)

![Dashboard - Admin View](screenshots/Screenshot 2026-05-05 221144.png)

![Access Logs View](screenshots/Screenshot 2026-05-05 221157.png)

![User Management View](screenshots/Screenshot 2026-05-05 221209.png)

---

## 10. ACKNOWLEDGEMENT

I would like to express my sincere gratitude to all those who have contributed to the successful completion of this project. This project would not have been possible without the support and guidance of many individuals.

I am especially thankful to my faculty coordinator for their valuable guidance, constant encouragement, and constructive feedback throughout the project. Their knowledge and expertise in Python programming, database management, and application security helped me understand the concepts effectively.

I would also like to thank the faculty members of the Department of Computer Science and Engineering at Lovely Professional University for providing a supportive academic environment that encouraged learning and innovation.

I am grateful to Lovely Professional University for providing the necessary resources and tools, including Python, Tkinter, SQLite, and Bcrypt, which were essential for completing this secure authentication project.

I would like to extend my thanks to my classmates and friends for their support and helpful suggestions during the development of this project.

Finally, I express my deepest gratitude to my family for their continuous support, patience, and encouragement throughout my academic journey.

**Rizzu Khan**  
**Registration No.: 12417714**

## APPENDIX

### A. AI-Generated Project Elaboration/Breakdown Report

**System Architecture Overview:**

The Secure User Authentication and Vault System is built using a three-tier architecture:

1. **Presentation Layer (Tkinter GUI)**
   - User interfaces for login, registration, and OTP verification
   - Dashboard for authenticated users
   - Admin management panels
   - Real-time error and success notifications

2. **Application Logic Layer (Python)**
   - Authentication engine with credential validation
   - OTP generation and management
   - Account lockout mechanism
   - Role-based access control
   - Audit logging system

3. **Data Storage Layer (SQLite)**
   - User credentials with bcrypt hashing
   - Audit logs with timestamps
   - Account lockout status
   - Role and permission data

**Security Implementation:**

The system implements multiple layers of security:
- **Password Security**: SHA-256 pre-hashing followed by Bcrypt hashing
- **Email Verification**: OTP-based 2FA with 2-minute validity
- **Brute Force Protection**: Account lockout after 5 failed attempts
- **Session Management**: Secure user data initialization and cleanup
- **Audit Trail**: Comprehensive logging of all authentication events
- **Input Validation**: Regex-based validation for usernames, emails, and passwords

**Database Schema:**

Users table stores:
- Username (unique constraint)
- Password hash (bcrypt format)
- Email address
- User role (admin/user)
- Failed attempt count
- Account lockout timestamp
- MFA secret (for future enhancement)

Audit logs table records:
- Username performing action
- Event description
- Timestamp of occurrence

---

### B. Problem Statement

**Problem:**
The need for a secure, multi-layered authentication system that:
1. Protects user credentials using industry-standard encryption
2. Implements multi-factor authentication for enhanced security
3. Prevents brute-force attacks through account lockout
4. Maintains detailed audit trails for security compliance
5. Provides role-based access control for different user types
6. Offers a user-friendly interface for authentication workflows

**Challenges Addressed:**
- Weak password attacks → Enforced strong password requirements
- Session hijacking → Secure session initialization and cleanup
- Credential stuffing → Account lockout mechanism
- Unauthorized access → Role-based access control
- Security audits → Comprehensive audit logging

---

### C. Solution/Code

#### Complete Application Code: `secuare.py`

```python
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import simpledialog
import bcrypt
import sqlite3
import random
import smtplib
import os
import re
import time
import hashlib
from datetime import datetime, timedelta

db = None
cursor = None
current_otp = ""
user_data = {}
current_otp_expiry = 0
otp_attempts = 0
otp_resend_count = 0
otp_last_sent_at = 0

MAX_USERNAME_LEN = 32
MAX_EMAIL_LEN = 254
OTP_TTL_SECONDS = 120
MAX_OTP_ATTEMPTS = 3
MAX_OTP_RESENDS = 3
OTP_RESEND_COOLDOWN_SECONDS = 30
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
DEFAULT_SMTP_EMAIL = "rizzukhansns0786@gmail.com"
DEFAULT_SMTP_APP_PASSWORD = "iwgz bomg vhno cypb"
DB_PATH = os.path.join(os.path.dirname(__file__), "secure_vault.db")

# [Complete code implementation follows - see secuare.py file for full code]
```

---

### D. Installation & Deployment Guide

#### Prerequisites:
```bash
Python 3.6 or higher
pip (Python package installer)
```

#### Installation Steps:
```bash
# 1. Clone the repository
git clone https://github.com/[YourUsername]/Secure-User-Authentication-Vault.git
cd Secure-User-Authentication-Vault

# 2. Install required packages
pip install -r requirements.txt

# 3. Configure SMTP (optional)
export SMTP_EMAIL="your-email@gmail.com"
export SMTP_APP_PASSWORD="your-app-password"

# 4. Run the application
python secuare.py
```

#### Requirements.txt:
```
bcrypt==4.0.1
```

---

### E. Configuration Reference

#### SMTP Configuration:
```json
{
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "use_tls": true,
  "sender_email": "your-email@gmail.com",
  "app_password": "your-16-character-app-password"
}
```

#### Environment Variables:
```bash
SMTP_EMAIL=your-email@gmail.com
SMTP_APP_PASSWORD=your-app-password
```

---

**End of Report**

---

*Report Generated: May 5, 2026*  
*Project: Secure User Authentication and Vault System*  
*Status: Complete with Future Roadmap*

