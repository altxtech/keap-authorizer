from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash
from keap_authorizer.db import get_db
from flask import render_template

# Authentication
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):

    # Username should not be empty
    if not username:
        return False

    # User must exist
    user = get_db().get_user(username)
    if user == None:
        return False

    # Password must be not None and of type str
    pwd = user.get("password")
    if not password or not isinstance(password, str):
        return False

    if not check_password_hash(pwd, password):
        return False
    
    return  user

@auth.get_user_roles
def get_user_roles(user):
    return user.get("roles")

@auth.error_handler
def auth_error(status):
    html = render_template("error.html", message = f"{status} - Unauthorized")
    return html, status
