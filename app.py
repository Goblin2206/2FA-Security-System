from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import time
import re

app = Flask(__name__)

# Secret key for session
app.secret_key = "2FA_Security_Project_2026"

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


# Create database
with app.app_context():
    db.create_all()



def is_sql_injection_attempt(value):

    patterns = [
        r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"['\"]\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1",
        r"\bor\s+1\s*=\s*1",
        r"\band\s+1\s*=\s*1",
        r"--",
        r"/\*",
        r"\*/",
        r";\s*(drop|delete|update|insert|select)\b",
        r"\bunion\s+select\b",
        r"\bdrop\s+table\b",
        r"\bdelete\s+from\b",
        r"\binsert\s+into\b",
        r"\bupdate\s+\w+\s+set\b"
    ]

    value = value.lower()

    for pattern in patterns:
        if re.search(pattern, value):
            return True

    return False


# =========================
# HOME
# =========================

@app.route("/")
def home():
    return redirect(url_for("login"))


# =========================
# REGISTER
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        # SQL Injection protection
        if (
            is_sql_injection_attempt(username)
            or is_sql_injection_attempt(email)
            or is_sql_injection_attempt(password)
        ):
            flash(
                "SQL Injection attempt detected and blocked!",
                "register_error"
            )
            return redirect(url_for("register"))

        # Check username
        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:
            flash(
                "Username already exists!",
                "register_error"
            )
            return redirect(url_for("register"))

        # Check email
        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:
            flash(
                "Email already registered!",
                "register_error"
            )
            return redirect(url_for("register"))

        # Password hashing
        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash(
            "Registration successful! Please login.",
            "register_success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        # SQL Injection protection
        if (
            is_sql_injection_attempt(username)
            or is_sql_injection_attempt(password)
        ):

            print("--------------------------------")
            print("SQL INJECTION ATTEMPT BLOCKED")
            print("Username:", username)
            print("--------------------------------")

            flash(
                "SQL Injection attempt detected and blocked!",
                "login_error"
            )

            return redirect(url_for("login"))

        # SQLAlchemy ORM query
        user = User.query.filter_by(
            username=username
        ).first()

        # Password verification
        if user and check_password_hash(
            user.password,
            password
        ):

            # Generate 6-digit OTP
            otp = str(
                random.randint(100000, 999999)
            )

            # Store OTP in session
            session["otp"] = otp
            session["otp_time"] = time.time()
            session["user_id"] = user.id

            # Display OTP in server logs
         
            print("--------------------------------")
            print("Generated OTP:", otp)
            print("--------------------------------")

            return redirect(
                url_for("verify_otp")
            )

        flash(
            "Invalid username or password!",
            "login_error"
        )

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    # User must login first
    if "otp" not in session:

        flash(
            "Please login first.",
            "login_error"
        )

        return redirect(url_for("login"))

    if request.method == "POST":

        entered_otp = request.form["otp"].strip()

        generated_otp = session.get("otp")
        otp_time = session.get("otp_time")

        # Check OTP expiry
        if otp_time is None or time.time() - otp_time > 60:

            session.pop("otp", None)
            session.pop("otp_time", None)

            flash(
                "OTP has expired! Please login again.",
                "otp_error"
            )

            return redirect(url_for("login"))

        # Check OTP
        if entered_otp == generated_otp:

            session["logged_in"] = True

            session.pop("otp", None)
            session.pop("otp_time", None)

            return redirect(
                url_for("dashboard")
            )

        else:

            flash(
                "Incorrect OTP! Please try again.",
                "otp_error"
            )

    return render_template("otp.html")



@app.route("/dashboard")
def dashboard():

    # Check login status
    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    user = User.query.get(
        session["user_id"]
    )

    if not user:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        username=user.username,
        email=user.email
    )


@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "logout_success"
    )

    return redirect(
        url_for("login")
    )




if __name__ == "__main__":

    app.run(
        debug=True
    )