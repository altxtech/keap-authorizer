import functools
from flask import Blueprint, request, render_template, url_for, redirect
from werkzeug.security import generate_password_hash
from keap_authorizer.db import get_db
from keap_authorizer.auth import auth
import secrets

bp = Blueprint("users", __name__, url_prefix="/users")

@bp.route("/")
@auth.login_required(role="admin")
def users():
    all_users = get_db().get_all_users()
    return render_template(
        "users.html",
        new_user_url=url_for("users.new_user"),
        users = all_users
    )

@bp.route("/new-user", methods=["GET", "POST"])
@auth.login_required(role="admin")
def new_user():

    if request.method == "GET":
        return render_template("new-user-form.html")

    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]
    roles = request.form["roles"].split(",")  # assuming roles are provided as a comma-separated string

    _create_user(username, password, email, roles)
    
    return redirect(url_for("users.users"))

def _create_user(username: str, password: str, email: str, roles: list[str]):

    # Add user 
    if not roles:
        roles = ["user"]

    # Insert the record in the database
    user = {
        "username": username,
        "email": email,
        "password": generate_password_hash(password),
        "reset_password": True, # User must reset password on first login
        "roles": roles
    }
    get_db().create_user(user)

# Reset password
# Users can reset their own passwrods
@bp.route("/<username>/reset-password", methods=["GET", "POST"])
@auth.login_required()
def reset_password(username: str):

    cur_user = auth.current_user()
    if not cur_user:
        raise Exception("User not logged in")

    # Users can only access their own profile
    is_admin = "admin" in cur_user["roles"]
    is_owner = cur_user["username"] == username
    if not is_admin and not is_owner:
        raise Exception("Unauthorized")

    if request.method == "GET":
        return render_template("reset-password-form.html", username=username)

    password = request.form["new_password"]
    confirm_password = request.form["new_password_confirm"]

    if password != confirm_password:
        return render_template("reset-password-form.html", username=username, error="Passwords do not match")

    # Update user
    updates = {
        "password": generate_password_hash(username + ":" + password),
        "reset_password": False
    }
    get_db().update_user(username, updates)

    return redirect(url_for("main.integrations"))


def check_reset_password(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user = auth.current_user()
        if user.get("reset_password"):
            return redirect(url_for("users.reset_password", username=user["username"]))
        return view(**kwargs)
    return wrapped_view
