import functools
from flask import Blueprint, request, render_template, url_for, redirect
from werkzeug.security import generate_password_hash
from keap_authorizer.db import get_db
from keap_authorizer.auth import auth
import re
from uuid import uuid4

bp = Blueprint("users", __name__, url_prefix="/users")

def check_reset_password(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user = auth.current_user()
        if user.get("reset_password"):
            return redirect(url_for("users.reset_password", username=user["username"]))
        return view(**kwargs)
    return wrapped_view

@bp.route("/")
@auth.login_required(role="admin")
@check_reset_password
def list_all():
    all_users = get_db().get_all_users()
    return render_template(
        "users.html",
        users = all_users
    )

@bp.route("/create", methods=["GET", "POST"])
@auth.login_required(role="admin")
@check_reset_password
def create():

    if request.method == "GET":
        return render_template("create-user-form.html")

    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]
    confirm_password = request.form["confirm_password"]
    roles = [role.strip().lower() for role in request.form["roles"].split(",")]  # assuming roles are provided as a comma-separated string

    # Validate data
    # Username should be unique
    errors = []
    if get_db().get_user_by_username(username):
        errors.append("Username already exists")
    
    print("Here")
    # Email is syntactically valid
    email_re = re.compile(r"[^@]+@[^@]+\.[^@]+")
    if not email_re.match(email):
        errors.append("Invalid email address")

    # Password is at least 8 characters long
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    # Passwords match
    if password != confirm_password:
        errors.append("Passwords do not match")

    # Roles must be valid
    if not roles:
        roles = ["user"]

    valid_roles = ["admin", "user"]
    for role in roles:
        if role not in valid_roles:
            errors.append(f"Invalid role: {role}")

    if errors:
        return render_template("create-user-form.html", errors=errors)

    # Insert the record in the database
    user = {
        "id": str(uuid4()), "username": username,
        "email": email,
        "password": generate_password_hash(password),
        "reset_password": True, # User must reset password on first login
        "roles": roles
    }
    get_db().create_user(user)
    print("here")
    return redirect(url_for("users.list_all"))

@bp.route("/<id>", methods=["GET"])
@auth.login_required(role="admin")
@check_reset_password
def view(id: str):

    user = get_db().get_user_by_id(id)
    return render_template("user.html", user=user)


@bp.route('/<id>/update', methods=["GET", "PUT"])
@auth.login_required(role="admin")
@check_reset_password
def update(id: str):

    if request.method == "GET":
        user = get_db().get_user_by_id(id)
        return render_template("update-user-form.html", user=user)

    # Update user
    email = request.form["email"]
    roles = [role.strip().lower() for role in request.form["roles"].split(",")]

    # Validate email
    errors = []
    email_re = re.compile(r"[^@]+@[^@]+\.[^@]+")
    if not email_re.match(email):
        errors.append("Invalid email address")

    # Validate roles
    valid_roles = ["admin", "user"]
    for role in roles:
        if role not in valid_roles:
            errors.append(f"Invalid role: {role}")

    if errors:
        user = get_db().get_user_by_id(id)
        return render_template("user.html", user=user, errors=errors)

    get_db().update_user(id, {"email": email, "roles": roles})
    return redirect(url_for("users.user", id=id))

# Reset password
# Users can reset their own passwrods
@bp.route("/<id>/reset-password", methods=["GET", "POST"])
@auth.login_required()
def reset_password(id: str):

    # Users can only access their own profile
    cur_user = auth.current_user()

    is_admin = "admin" in cur_user["roles"]
    is_owner = cur_user["id"] == id

    if not is_admin and not is_owner:
        raise redirect(url_for("main.integrations", errors=["You do not have permission to access this page"]))

    if request.method == "GET":
        return render_template("reset-password-form.html", user_id=id)

    password = request.form["new_password"]
    confirm_password = request.form["new_password_confirm"]

    if password != confirm_password:
        return render_template("reset-password-form.html", user_id=id, errors=["Passwords do not match"])

    # If the password is being reset by and admin, the user will be required to reset their pasword
    reset_password = is_admin
    updates = {
        "password": generate_password_hash(password),
        "reset_password": reset_password
    }
    get_db().update_user(id, updates)

    return redirect(url_for("users.user",  id=id))

@bp.route("/<id>/delete", methods=["GET", "DELETE"])
@auth.login_required(role="admin")
@check_reset_password
def delete(id: str):

    if request.method == "GET":
        user = get_db().get_user_by_id(id)
        return render_template("confirm-delete-user.html", user=user)

    get_db().delete_user(id)
    return redirect(url_for("users.list_all"))
