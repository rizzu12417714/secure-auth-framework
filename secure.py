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


def parse_db_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None

# ---------------- DATABASE SETUP ---------------- #
def init_db():
    global db, cursor
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT NULL,
                mfa_secret TEXT,
                salt BLOB
            )
            """
        )

        # Keep compatibility with pre-existing databases.
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until TEXT NULL")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        except Exception:
            pass

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                event TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.commit()
    except Exception as e:
        db, cursor = None, None
        print(f"Database Error: {e}")

def load_smtp_credentials():
    sender = os.getenv("SMTP_EMAIL", "").strip()
    app_password = os.getenv("SMTP_APP_PASSWORD", "").strip()
    if sender and app_password:
        return sender, app_password, ""

    # Zero-config fallback for quick start.
    if DEFAULT_SMTP_EMAIL and DEFAULT_SMTP_APP_PASSWORD:
        return DEFAULT_SMTP_EMAIL, DEFAULT_SMTP_APP_PASSWORD, ""

    return "", "", "SMTP credentials are not configured"


def send_otp(email):
    otp = str(random.randint(100000, 999999))
    sender, app_password, cred_error = load_smtp_credentials()
    if cred_error:
        return "", False, cred_error

    try:
        message = f"Subject: OTP Verification\n\nYour OTP is: {otp}"
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, app_password)
        server.sendmail(sender, email, message)
        server.quit()
        return otp, True, ""
    except Exception as e:
        return "", False, f"Failed to send OTP email: {e}"


def log_event(username, event):
    if cursor is None or db is None:
        return
    try:
        cursor.execute(
            "INSERT INTO audit_logs (username, event) VALUES (?, ?)",
            (username, event),
        )
        db.commit()
    except Exception:
        pass


def validate_email(email):
    return re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email) is not None


def validate_username(username):
    return re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username) is not None


def validate_password(password):
    if len(password) < 1:
        return False
    has_upper = re.search(r"[A-Z]", password)
    has_lower = re.search(r"[a-z]", password)
    has_digit = re.search(r"\d", password)
    has_special = re.search(r"[^A-Za-z0-9]", password)
    return all([has_upper, has_lower, has_digit, has_special])

def normalize_password_for_bcrypt(password):
    # Pre-hash to support arbitrary password lengths safely with bcrypt.
    return hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")

def mask_email(email):
    if not email or "@" not in email:
        return email
    local_part, domain_part = email.split("@", 1)
    if len(local_part) <= 2:
        masked_local = local_part[0] + "*" * max(1, len(local_part) - 1)
    else:
        masked_local = local_part[:2] + "*" * (len(local_part) - 2)

    domain_name, dot, domain_suffix = domain_part.partition(".")
    if domain_name:
        if len(domain_name) <= 2:
            masked_domain = domain_name[0] + "*" * max(1, len(domain_name) - 1)
        else:
            masked_domain = domain_name[:2] + "*" * (len(domain_name) - 2)
        return f"{masked_local}@{masked_domain}{dot}{domain_suffix}"

    return f"{masked_local}@{domain_part}"

# ---------------- NAVIGATION ---------------- #
def show_frame(frame):
    frame.tkraise()

# ---------------- LOGIC ---------------- #
def handle_register():
    u, p, e = reg_user.get().strip(), reg_pass.get().strip(), reg_email.get().strip()
    if not u or not p or not e or u == "Username":
        messagebox.showerror("Error", "All fields are required")
        return

    if len(u) > MAX_USERNAME_LEN or len(e) > MAX_EMAIL_LEN:
        messagebox.showerror("Error", "Input exceeds allowed length")
        return

    if not validate_username(u):
        messagebox.showerror("Error", "Username must be 3-32 chars (letters, numbers, _.-)")
        return

    if not validate_email(e):
        messagebox.showerror("Error", "Please enter a valid email address")
        return

    if not validate_password(p):
        messagebox.showerror(
            "Error",
            "Password must include uppercase, lowercase, number, and special character",
        )
        return

    if cursor is None or db is None:
        messagebox.showerror("Error", "Database connection is not available")
        return
    
    hashed = bcrypt.hashpw(normalize_password_for_bcrypt(p), bcrypt.gensalt()).decode("utf-8")
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, role) VALUES (?,?,?,?)",
            (u, hashed, e, "user"),
        )
        db.commit()
        log_event(u, "User registration successful")
        messagebox.showinfo("Success", "Account created successfully. Please sign in.")
        show_frame(login_frame)
    except Exception:
        log_event(u, "User registration failed (duplicate or DB error)")
        messagebox.showerror("Error", "An account with this username already exists")

def handle_login():
    u, p = entry_user.get().strip(), entry_pass.get().strip()

    if len(u) > MAX_USERNAME_LEN:
        messagebox.showerror("Error", "Invalid credentials format")
        return

    if cursor is None:
        messagebox.showerror("Error", "Database connection is not available")
        return

    cursor.execute(
        "SELECT id, password_hash, email, role, failed_attempts, locked_until FROM users WHERE username=?",
        (u,),
    )
    result = cursor.fetchone()

    if result:
        user_id = result[0]
        stored_hash = result[1]
        email = result[2] or ""
        role = result[3]
        failed_attempts = result[4] or 0
        locked_until = parse_db_datetime(result[5])
        if locked_until and locked_until > datetime.now():
            mins_left = int((locked_until - datetime.now()).total_seconds() // 60) + 1
            messagebox.showerror("Error", f"Account locked. Try again in {mins_left} minute(s)")
            log_event(u, "Blocked login attempt on locked account")
            return

        # MySQL can return hash as bytes/bytearray/string depending on connector settings.
        if isinstance(stored_hash, str):
            hash_bytes = stored_hash.encode("utf-8")
        else:
            hash_bytes = bytes(stored_hash)

        if bcrypt.checkpw(normalize_password_for_bcrypt(p), hash_bytes):
            cursor.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user_id,))
            db.commit()

            if email:
                issue_otp_for_email(email, "Username/password login", preferred_username=u, preferred_role=role)
            else:
                user_data.clear()
                user_data.update({"username": u, "role": role, "email": ""})
                log_event(u, "Login successful without OTP email on record")
                refresh_dashboard_view()
                show_frame(dashboard_frame)
        else:
            new_failed = (failed_attempts or 0) + 1
            lock_until = None
            if new_failed >= MAX_LOGIN_ATTEMPTS:
                lock_until = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
                new_failed = 0

            cursor.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                (new_failed, lock_until, user_id),
            )
            db.commit()
            log_event(u, "Invalid password attempt")
            messagebox.showerror("Error", "Invalid password")
    else:
        log_event(u, "Login attempt for unknown user")
        messagebox.showerror("Error", "User account not found")

def issue_otp_for_email(email, login_source, preferred_username=None, preferred_role=None):
    global current_otp, current_otp_expiry, otp_attempts, otp_resend_count, otp_last_sent_at, user_data

    if not validate_email(email):
        messagebox.showerror("Error", "Please enter a valid email address")
        return False

    if cursor is None:
        messagebox.showerror("Error", "Database connection is not available")
        return False

    cursor.execute("SELECT username, role FROM users WHERE email=? ORDER BY id ASC LIMIT 1", (email,))
    result = cursor.fetchone()
    if not result:
        messagebox.showerror("Error", "No account found for this email")
        return False

    username, role = result
    if preferred_username is not None:
        username = preferred_username
    if preferred_role is not None:
        role = preferred_role

    otp, delivered, reason = send_otp(email)
    if not delivered:
        log_event(username, f"{login_source} OTP failed: {reason}")
        messagebox.showerror("Error", f"OTP email was not sent: {reason}")
        return False

    current_otp = otp
    current_otp_expiry = time.time() + OTP_TTL_SECONDS
    otp_attempts = 0
    otp_resend_count = 0
    otp_last_sent_at = time.time()
    user_data = {"username": username, "role": role, "email": email}
    otp_label_var.set(f"Verification code sent to:\n{mask_email(email)}\nValid for 2 minutes")
    log_event(username, f"{login_source} OTP challenge issued")
    show_frame(otp_frame)
    return True

def handle_social_login(provider_name):
    email = simpledialog.askstring(
        f"{provider_name} Login",
        f"Enter your {provider_name} account email:",
        parent=root,
    )

    if email is None:
        return

    issue_otp_for_email(email.strip(), f"{provider_name} login")

def verify_otp_logic():
    global otp_attempts
    if time.time() > current_otp_expiry:
        log_event(user_data.get("username", "unknown"), "OTP expired")
        messagebox.showerror("Error", "OTP has expired. Please sign in again")
        show_frame(login_frame)
        return

    if entry_otp.get() == current_otp:
        log_event(user_data.get("username", "unknown"), "MFA verification successful")
        refresh_dashboard_view()
        show_frame(dashboard_frame)
    else:
        otp_attempts += 1
        log_event(user_data.get("username", "unknown"), "Invalid OTP attempt")
        if otp_attempts >= MAX_OTP_ATTEMPTS:
            messagebox.showerror("Error", "Too many invalid OTP attempts. Please sign in again")
            show_frame(login_frame)
            return
        messagebox.showerror("Error", "Invalid OTP code")

def resend_otp_logic():
    global current_otp, current_otp_expiry, otp_attempts, otp_resend_count, otp_last_sent_at
    username = user_data.get("username", "unknown")
    email = user_data.get("email", "")

    if not email:
        messagebox.showerror("Error", "Email is unavailable. Please sign in again")
        show_frame(login_frame)
        return

    if otp_resend_count >= MAX_OTP_RESENDS:
        log_event(username, "OTP resend blocked: max resend limit reached")
        messagebox.showerror("Error", "Resend limit reached. Please sign in again")
        show_frame(login_frame)
        return

    wait_seconds = int(OTP_RESEND_COOLDOWN_SECONDS - (time.time() - otp_last_sent_at))
    if wait_seconds > 0:
        messagebox.showinfo("Information", f"You can request a new OTP in {wait_seconds} second(s)")
        return

    otp, delivered, reason = send_otp(email)
    if not delivered:
        log_event(username, f"OTP resend failed: {reason}")
        messagebox.showerror("Error", "Resend failed. Check SMTP setup and try again.")
        return

    current_otp = otp
    current_otp_expiry = time.time() + OTP_TTL_SECONDS
    otp_attempts = 0
    otp_resend_count += 1
    otp_last_sent_at = time.time()
    entry_otp.delete(0, tk.END)
    otp_label_var.set(
        f"Verification code sent to:\n{mask_email(email)}\nValid for 2 minutes\nResends used: {otp_resend_count}/{MAX_OTP_RESENDS}"
    )
    log_event(username, "OTP resent successfully")
    messagebox.showinfo("Success", "A new OTP has been sent to your email address")

def open_user_management():
    if cursor is None:
        messagebox.showerror("Error", "Database connection is not available")
        return

    if user_data.get("role") != "admin":
        log_event(user_data.get("username", "unknown"), "Unauthorized user management access")
        messagebox.showerror("Access Denied", "Admin access required. Only administrators can manage users.")
        return

    manage_win = tk.Toplevel(root)
    manage_win.title("User Management")
    manage_win.geometry("400x400")
    tk.Label(manage_win, text="Registered OS Users", font=("Arial", 12, "bold")).pack(pady=10)
    
    cursor.execute("SELECT id, username, role FROM users")
    for u in cursor.fetchall():
        tk.Label(manage_win, text=f"ID: {u[0]} | Name: {u[1]} | Role: {u[2]}", anchor="w").pack(fill="x", padx=20)

def open_access_logs():
    if cursor is None:
        messagebox.showerror("Error", "Database connection is not available")
        return

    if user_data.get("role") != "admin":
        messagebox.showerror("Access Denied", "Admin access required. Only administrators can view access logs.")
        return

    logs_win = tk.Toplevel(root)
    logs_win.title("Access Logs")
    logs_win.geometry("700x400")
    tk.Label(logs_win, text="Latest Security Events", font=("Arial", 12, "bold")).pack(pady=10)

    listbox = tk.Listbox(logs_win, width=100, height=18)
    listbox.pack(fill="both", expand=True, padx=15, pady=10)

    cursor.execute("SELECT username, event, timestamp FROM audit_logs ORDER BY id DESC LIMIT 100")
    for row in cursor.fetchall():
        listbox.insert("end", f"[{row[2]}] {row[0]} -> {row[1]}")

def handle_logout():
    global current_otp, current_otp_expiry, otp_attempts, otp_resend_count, otp_last_sent_at, user_data
    log_event(user_data.get("username", "unknown"), "User logged out")
    current_otp = ""
    current_otp_expiry = 0
    otp_attempts = 0
    otp_resend_count = 0
    otp_last_sent_at = 0
    user_data = {}
    entry_pass.delete(0, tk.END)
    entry_otp.delete(0, tk.END)
    show_frame(login_frame)

def refresh_dashboard_view():
    username = user_data.get("username", "UNKNOWN")
    role = user_data.get("role", "user")
    email = user_data.get("email", "")
    failed_attempts = 0
    lock_state = "Unlocked"
    total_users = 0
    total_logs = 0
    last_login_text = "No login record"
    health_text = "Healthy"

    if cursor is not None:
        try:
            cursor.execute("SELECT failed_attempts, locked_until FROM users WHERE username=?", (username,))
            row = cursor.fetchone()
            if row:
                failed_attempts = row[0] or 0
                locked_until = parse_db_datetime(row[1])
                if locked_until and locked_until > datetime.now():
                    lock_state = f"Locked until {locked_until.strftime('%d %b %H:%M')}"
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0] or 0
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total_logs = cursor.fetchone()[0] or 0
            cursor.execute(
                """
                SELECT timestamp, event
                FROM audit_logs
                WHERE username=? AND (event LIKE ? OR event LIKE ?)
                ORDER BY id DESC LIMIT 1
                """,
                (username, "%MFA verification successful%", "%Login successful without OTP email on record%"),
            )
            login_row = cursor.fetchone()
            if login_row:
                last_login_text = f"{login_row[0]}"

            if lock_state != "Unlocked":
                health_text = "Attention needed"
            elif failed_attempts >= 3:
                health_text = "At risk"
            elif total_logs == 0:
                health_text = "Needs review"
            elif role == "admin":
                health_text = "Protected"
        except Exception:
            pass

    dash_title.set(f"Welcome, {username.upper()}")
    profile_name_var.set(username)
    profile_role_var.set(role.upper())
    profile_email_var.set(mask_email(email) if email else "Not available")
    profile_status_var.set(lock_state)
    attempts_var.set(str(failed_attempts))
    otp_state_var.set("Enabled" if email else "Offline")
    users_count_var.set(str(total_users))
    logs_count_var.set(str(total_logs))
    last_login_var.set(last_login_text)
    health_var.set(health_text)

    if role == "admin":
        admin_btn.pack(pady=10, padx=10, fill="x")
    else:
        admin_btn.pack_forget()

    activity_listbox.delete(0, tk.END)
    if cursor is None:
        activity_listbox.insert(tk.END, "No audit log data available")
        return

    try:
        if role == "admin":
            cursor.execute("SELECT username, event, timestamp FROM audit_logs ORDER BY id DESC LIMIT 6")
        else:
            cursor.execute("SELECT username, event, timestamp FROM audit_logs WHERE username=? ORDER BY id DESC LIMIT 6", (username,))
        rows = cursor.fetchall()
        if not rows:
            activity_listbox.insert(tk.END, "No recent security events yet")
            return
        for row in rows:
            activity_listbox.insert(tk.END, f"{row[2]}  |  {row[1]}")
    except Exception:
        activity_listbox.insert(tk.END, "Unable to load activity history")

# ---------------- UI SETUP ---------------- #
root = tk.Tk()
root.title("Secure OS Auth Framework")
root.geometry("1100x680") # Wider for Dashboard layout

container = tk.Frame(root)
container.pack(fill="both", expand=True)
container.grid_rowconfigure(0, weight=1)
container.grid_columnconfigure(0, weight=1)

# Frame Styles
login_frame = tk.Frame(container, bg="#1a1c2c")
register_frame = tk.Frame(container, bg="#1a1c2c")
otp_frame = tk.Frame(container, bg="#ffffff")
dashboard_frame = tk.Frame(container, bg="#f4f7f6")

for frame in (login_frame, register_frame, otp_frame, dashboard_frame):
    frame.grid(row=0, column=0, sticky="nsew")

# --- MODERN LOGIN & REGISTER FRAME ---
login_inner = tk.Frame(login_frame, bg="#1a1c2c")
login_inner.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(login_inner, text="🛡️ OS SECURITY HUB", font=("Impact", 28), fg="#00d2ff", bg="#1a1c2c").pack(pady=20)

tk.Label(login_inner, text="Username", fg="white", bg="#1a1c2c").pack(anchor="w")
entry_user = tk.Entry(login_inner, width=35, font=("Arial", 11), bd=0); entry_user.pack(pady=5, ipady=5)

tk.Label(login_inner, text="Password", fg="white", bg="#1a1c2c").pack(anchor="w")
entry_pass = tk.Entry(login_inner, width=35, font=("Arial", 11), show="*", bd=0); entry_pass.pack(pady=5, ipady=5)

tk.Button(login_inner, text="SIGN IN", bg="#00d2ff", fg="#1a1c2c", font=("Arial", 10, "bold"), 
          width=30, bd=0, command=handle_login, cursor="hand2").pack(pady=20)

ttk.Separator(login_inner, orient="horizontal").pack(fill="x", pady=8)
tk.Label(login_inner, text="Or continue with", fg="#d6eaf8", bg="#1a1c2c").pack(pady=6)
tk.Button(login_inner, text="LOGIN WITH GOOGLE", bg="#db4437", fg="white", font=("Arial", 9, "bold"),
          width=30, bd=0, command=lambda: handle_social_login("Google")).pack(pady=4)
tk.Button(login_inner, text="LOGIN WITH GITHUB", bg="#24292e", fg="white", font=("Arial", 9, "bold"),
          width=30, bd=0, command=lambda: handle_social_login("GitHub")).pack(pady=4)

register_link = tk.Label(
    login_inner,
    text="New user? Register here",
    fg="#5dade2",
    bg="#1a1c2c",
    cursor="hand2",
    font=("Arial", 10, "underline"),
)
register_link.pack(pady=12)
register_link.bind("<Button-1>", lambda event: show_frame(register_frame))

# --- REGISTER FRAME ---
register_inner = tk.Frame(register_frame, bg="#1a1c2c")
register_inner.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(register_inner, text="Create New Account", font=("Impact", 24), fg="#00d2ff", bg="#1a1c2c").pack(pady=15)
tk.Label(register_inner, text="Username", fg="white", bg="#1a1c2c").pack(anchor="w")
reg_user = tk.Entry(register_inner, width=35, font=("Arial", 10)); reg_user.pack(pady=4, ipady=4)
tk.Label(register_inner, text="Password", fg="white", bg="#1a1c2c").pack(anchor="w")
reg_pass = tk.Entry(register_inner, width=35, font=("Arial", 10), show="*"); reg_pass.pack(pady=4, ipady=4)
tk.Label(register_inner, text="Email Address", fg="white", bg="#1a1c2c").pack(anchor="w")
reg_email = tk.Entry(register_inner, width=35, font=("Arial", 10)); reg_email.pack(pady=4, ipady=4)

tk.Button(register_inner, text="REGISTER ACCOUNT", bg="#2c3e50", fg="white", font=("Arial", 9), 
          width=30, bd=0, command=handle_register).pack(pady=10)
tk.Button(register_inner, text="BACK TO LOGIN", bg="#34495e", fg="white", font=("Arial", 9),
          width=30, bd=0, command=lambda: show_frame(login_frame)).pack(pady=4)

# --- OTP FRAME ---
otp_label_var = tk.StringVar()
tk.Label(otp_frame, text="Two-Factor Authentication (2FA)", font=("Arial", 20, "bold"), bg="white").pack(pady=50)
tk.Label(otp_frame, textvariable=otp_label_var, bg="white", font=("Arial", 11)).pack(pady=10)
entry_otp = tk.Entry(otp_frame, font=("Arial", 24), width=8, justify="center", bd=2); entry_otp.pack(pady=20)
tk.Button(otp_frame, text="VERIFY OTP", bg="#27ae60", fg="white", font=("Arial", 12, "bold"), 
          padx=20, pady=10, command=verify_otp_logic, bd=0).pack(pady=20)
tk.Button(otp_frame, text="RESEND OTP", bg="#2980b9", fg="white", font=("Arial", 10, "bold"),
          padx=20, pady=8, command=resend_otp_logic, bd=0).pack(pady=5)

# --- MODERN DASHBOARD FRAME DESIGN ---
sidebar = tk.Frame(dashboard_frame, bg="#263444", width=210)
sidebar.pack(side="left", fill="y")

tk.Label(sidebar, text="OS SECURITY HUB", font=("Arial", 13, "bold"), fg="#ecf0f1", bg="#263444", pady=24).pack()
tk.Label(sidebar, text="Secure control panel", font=("Arial", 9), fg="#aeb6bf", bg="#263444").pack(pady=(0, 12))

sidebar_divider = tk.Frame(sidebar, bg="#3f5368", height=1)
sidebar_divider.pack(fill="x", padx=16, pady=(0, 16))

def make_sidebar_button(parent, text, command, bg="#34495e"):
    return tk.Button(
        parent,
        text=text,
        bg=bg,
        fg="white",
        activebackground="#3d566e",
        activeforeground="white",
        font=("Arial", 10, "bold"),
        bd=0,
        pady=10,
        width=20,
        command=command,
        cursor="hand2",
    )

hero_panel = tk.Frame(dashboard_frame, bg="#f4f7f6")
hero_panel.pack(side="top", fill="x", padx=28, pady=(18, 0))

dash_title = tk.StringVar()
tk.Label(hero_panel, textvariable=dash_title, font=("Arial", 24, "bold"), bg="#f4f7f6", fg="#1f2d3d").pack(anchor="w")
tk.Label(
    hero_panel,
    text="Centralized access control, user registry, and audit visibility for the OS security layer.",
    font=("Arial", 10),
    bg="#f4f7f6",
    fg="#6c7a89",
).pack(anchor="w", pady=(6, 0))

content_area = tk.Frame(dashboard_frame, bg="#f4f7f6")
content_area.pack(side="right", fill="both", expand=True, padx=30, pady=18)

summary_row = tk.Frame(content_area, bg="#f4f7f6")
summary_row.pack(fill="x", pady=(18, 16))

def create_card(parent, text, value_var, color):
    card = tk.Frame(parent, bg="white", padx=18, pady=18, highlightbackground="#dcdde1", highlightthickness=1)
    card.pack(side="left", padx=8, expand=True, fill="both")
    tk.Label(card, text=text, font=("Arial", 9), bg="white", fg="#7f8c8d").pack(anchor="w")
    tk.Label(card, textvariable=value_var, font=("Arial", 16, "bold"), bg="white", fg=color).pack(anchor="w", pady=(4, 0))
    return card

profile_name_var = tk.StringVar(value="-")
profile_role_var = tk.StringVar(value="-")
profile_email_var = tk.StringVar(value="-")
profile_status_var = tk.StringVar(value="-")
attempts_var = tk.StringVar(value="0")
otp_state_var = tk.StringVar(value="-")
users_count_var = tk.StringVar(value="0")
logs_count_var = tk.StringVar(value="0")
last_login_var = tk.StringVar(value="-")
health_var = tk.StringVar(value="Healthy")

create_card(summary_row, "System Status", tk.StringVar(value="ENCRYPTED"), "#27ae60")
create_card(summary_row, "Security Protocol", tk.StringVar(value="AES-256 / BCRYPT"), "#2980b9")
create_card(summary_row, "OTP Channel", otp_state_var, "#8e44ad")
create_card(summary_row, "Users Registered", users_count_var, "#e67e22")
create_card(summary_row, "Audit Logs", logs_count_var, "#c0392b")
create_card(summary_row, "Last Login", last_login_var, "#2c3e50")

health_row = tk.Frame(content_area, bg="#f4f7f6")
health_row.pack(fill="x", pady=(0, 16))
create_card(health_row, "Security Health", health_var, "#16a085")

dashboard_body = tk.Frame(content_area, bg="#f4f7f6")
dashboard_body.pack(fill="both", expand=True)

left_panel = tk.Frame(dashboard_body, bg="#f4f7f6")
left_panel.pack(side="left", fill="both", expand=True, padx=(0, 12))

right_panel = tk.Frame(dashboard_body, bg="#f4f7f6")
right_panel.pack(side="right", fill="y", padx=(12, 0))

profile_card = tk.Frame(left_panel, bg="white", padx=18, pady=18, highlightbackground="#dcdde1", highlightthickness=1)
profile_card.pack(fill="x", pady=(0, 14))
tk.Label(profile_card, text="Account Snapshot", font=("Arial", 12, "bold"), bg="white", fg="#1f2d3d").pack(anchor="w")
for label_text, value_var in [
    ("Username", profile_name_var),
    ("Role", profile_role_var),
    ("Email", profile_email_var),
    ("Lock Status", profile_status_var),
    ("Failed Attempts", attempts_var),
]:
    row = tk.Frame(profile_card, bg="white")
    row.pack(fill="x", pady=4)
    tk.Label(row, text=label_text, font=("Arial", 9), bg="white", fg="#7f8c8d", width=16, anchor="w").pack(side="left")
    tk.Label(row, textvariable=value_var, font=("Arial", 10, "bold"), bg="white", fg="#2c3e50", anchor="w").pack(side="left")

quick_actions = tk.Frame(left_panel, bg="white", padx=18, pady=18, highlightbackground="#dcdde1", highlightthickness=1)
quick_actions.pack(fill="x", pady=(0, 14))
tk.Label(quick_actions, text="Quick Actions", font=("Arial", 12, "bold"), bg="white", fg="#1f2d3d").pack(anchor="w")
tk.Label(quick_actions, text="Common admin and security operations for this project.", font=("Arial", 9), bg="white", fg="#7f8c8d").pack(anchor="w", pady=(2, 10))

actions_row = tk.Frame(quick_actions, bg="white")
actions_row.pack(fill="x")
tk.Button(actions_row, text="Open Access Logs", bg="#34495e", fg="white", font=("Arial", 10, "bold"), bd=0, pady=10, command=open_access_logs).pack(side="left", padx=(0, 8), fill="x", expand=True)
tk.Button(actions_row, text="Manage Users", bg="#16a085", fg="white", font=("Arial", 10, "bold"), bd=0, pady=10, command=open_user_management).pack(side="left", padx=8, fill="x", expand=True)
tk.Button(actions_row, text="Sign Out", bg="#e74c3c", fg="white", font=("Arial", 10, "bold"), bd=0, pady=10, command=handle_logout).pack(side="left", padx=(8, 0), fill="x", expand=True)

activity_card = tk.Frame(right_panel, bg="white", padx=18, pady=18, width=320, highlightbackground="#dcdde1", highlightthickness=1)
activity_card.pack(fill="y", expand=False)
tk.Label(activity_card, text="Recent Activity", font=("Arial", 12, "bold"), bg="white", fg="#1f2d3d").pack(anchor="w")
tk.Label(activity_card, text="Latest security events from the audit trail.", font=("Arial", 9), bg="white", fg="#7f8c8d").pack(anchor="w", pady=(2, 10))
activity_listbox = tk.Listbox(activity_card, height=18, width=44, bd=0, highlightthickness=0, activestyle="none")
activity_listbox.pack(fill="both", expand=True)

# Sidebar Action Buttons
admin_btn = make_sidebar_button(sidebar, "👥 Manage Users", open_user_management, bg="#16a085")

make_sidebar_button(sidebar, "📜 View Access Logs", open_access_logs).pack(pady=5, padx=10)

make_sidebar_button(
    sidebar,
    "🔒 Security Center",
    lambda: messagebox.showinfo("Security Center", "Security controls are active and audit logging is enabled."),
    bg="#5d6d7e",
).pack(pady=5, padx=10)

make_sidebar_button(sidebar, "SIGN OUT", handle_logout, bg="#e74c3c").pack(side="bottom", pady=30, padx=10)

init_db()
refresh_dashboard_view()
show_frame(login_frame)
root.mainloop()
