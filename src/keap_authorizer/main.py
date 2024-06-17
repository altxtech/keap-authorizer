from flask import Blueprint, request, Flask, render_template, url_for, redirect, session, current_app
from werkzeug.security import generate_password_hash 

import os
import urllib.parse
import json
import requests 
from datetime import datetime
from uuid import uuid4
import re

from keap_authorizer.auth import auth
from keap_authorizer.db import get_db


def _create_user(username, password, roles):

    if not roles: # Empty string or null
        roles = ["user"]

    user = {
            "username": username,
            "password": generate_password_hash(password),
            "roles": roles
    }
    get_db().create_user(user)
    


# Keap stuff
def keap_auth_url(state):
    base_url = "https://accounts.infusionsoft.com/app/oauth/authorize" # Can be hardcoded
    params = {
        "client_id": current_app.config["KEAP_CLIENT_ID"],
        "redirect_uri": current_app.config["HOST"] + url_for('main.new_integration_auth_callback'),
        "scope": "full",
        "response_type": "code",
        "state": state
    }
    return base_url + "?" + urllib.parse.urlencode(params)

def _gen_handle(name):
    """
    Generate a URL-friendly handle from the given name.
    - Convert to lowercase
    - Replace spaces with hyphens
    - Remove non-alphanumeric characters except hyphens
    """
    handle = name.lower()
    handle = handle.replace(" ", "-")
    handle = re.sub(r"[^a-z0-9-]", "", handle)
    return handle

# Routes
main = Blueprint("main", __name__)

@main.route("/")
def index():
    return redirect(url_for("main.integrations"))

@main.route("/users")
@auth.login_required(role="admin")
def users():

    all_users = get_db().get_all_users()
    print(all_users)
    return render_template(
        "users.html",
        new_user_url=url_for("main.new_user"),
        users = all_users
    )

@main.route("/users/new-user", methods=["GET", "POST"])
@auth.login_required(role="admin")
def new_user():
    if request.method == "GET":
        return render_template("new-user-form.html")
    username = request.form["username"]
    password = request.form["password"]
    roles = request.form["roles"].split(",")  # assuming roles are provided as a comma-separated string
    _create_user(username, password, roles)
    return redirect(url_for("main.users"))


@main.route("/integrations")
@auth.login_required
def integrations():
    all_integrations = get_db().get_all_integrations() 
    return render_template(
        "integrations.html",
        integrations=all_integrations,
        new_integration_url=url_for("main.new_integration")
    )

# TODO - Aditional requirements
# - If the user the user is not authenticated, it should be redirected to the login page
# - After login, ideally they should be redirected to the page they were trying to access, but should at least be redirected to integrations page

@main.route("/integrations/new-integration", methods=["GET", "POST"])
@auth.login_required
def new_integration():
    if request.method == "GET":
        '''
        Form:
            Name -> Display name for integration
        Form should auto suggest an identifier if possible
        '''
        return render_template("new-integration-form.html")
    
    name = request.form["name"]
    
    # Check if the name is unique
    existing_integrations = get_db().get_all_integrations()
    for integration in existing_integrations:
        if integration["name"] == name:
            return render_template("new-integration-form.html", error="Name must be unique")

    state = json.dumps({"name": name})
    return redirect(keap_auth_url(state))

@main.route("/integrations/new-integration/auth/callback")
@auth.login_required
def new_integration_auth_callback():
    # Create new integration object
    state = json.loads(request.args["state"])
    new_integration = {
        "id": str(uuid4()),  # Ensure the UUID is a string for JSON serialization
        "name": state["name"],
        "handle": _gen_handle(state["name"]),
        "created_at": None,
        "updated_at": None,
        "type": "Keap",  # Planning to extend this app for other types of connections in the future
    }

    keap_details = {}  # Relevant data specific for the Keap integration

    # 1. Finish the OAuth flow
    auth_code = request.args["code"]
    form_data = {
        "client_id": current_app.config["KEAP_CLIENT_ID"],
        "client_secret": current_app.config["KEAP_CLIENT_SECRET"],
        "code": auth_code,
        "grant_type": "authorization_code",
        "redirect_uri": current_app.config["HOST"] + url_for('main.new_integration_auth_callback')
    }
    r = requests.post("https://api.infusionsoft.com/token", data=form_data)
    r.raise_for_status()  # Ensure the request was successful
    response_data = r.json()
    keap_details["scope"] = response_data["scope"]
    keap_details["app_id"] = keap_details["scope"].split("|")[1].split(".")[0]
    access_token = response_data["access_token"]
    refresh_token = response_data["refresh_token"]

    # Research business profile
    h = {"Authorization": f"Bearer {access_token}"}
    r = requests.get("https://api.infusionsoft.com/crm/rest/v2/businessProfile", headers=h)
    r.raise_for_status()  # Ensure the request was successful

    # Store customer info in the database, capture lead for sg
    profile = r.json()
    keap_details["name"] = profile["name"]

    '''
    # Lead Capture
    # List users of the connected account
    r = requests.get("https://api.infusionsoft.com/crm/rest/v1/users", headers=h)
    r.raise_for_status()
    users = r.json()["users"]

    # There is a ton of validation rules for contacts.
    # Better to keep things simple and add complexity slowly

    lead_payload_template = {
        "email_addresses": [],
        "given_name": "",
        "family_name": "",
        "source_type": "API",
    }
    
    lead_headers = {
        "Authorization": "Bearer " + current_app.config["MAIN_KEAP_ACCESS_TOKEN"],
        "Content-Type": "application/json"
    }

    for user in users:
        lead_payload = lead_payload_template.copy()
        lead_payload["given_name"] = user["given_name"]
        lead_payload["family_name"] = user["family_name"]
        lead_payload["email_addresses"].append({"email": user["email_address"], "field": "EMAIL2"})


        r = requests.post("https://api.infusionsoft.com/crm/rest/v2/contacts", headers=lead_headers, json=lead_payload)
        print(r.text)
        r.raise_for_status()
    '''


    # Deploy Airbyte destination
    payload = {
        "name": new_integration["handle"] + "/" + "keap",
        "definitionId": current_app.config["AIRBYTE_DESTINATION_KEAP_DEFINITION_ID"],
        "workspaceId": current_app.config["AIRBYTE_WORKSPACE_ID"],
        "configuration": {
            "client_id": current_app.config["KEAP_CLIENT_ID"],
            "client_secret": current_app.config["KEAP_CLIENT_SECRET"],
            "keap_app_id": keap_details["app_id"],
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    }
    r = requests.post(
        current_app.config["AIRBYTE_API_URL"] + "/destinations",
        auth=(current_app.config["AIRBYTE_USERNAME"], current_app.config["AIRBYTE_PASSWORD"]),
        json=payload
    )
    r.raise_for_status()  # Ensure the request was successful
    keap_details["airbyte_destination_id"] = r.json()["destinationId"]
    new_integration["details"] = keap_details

    new_integration["ref"] = keap_details["app_id"] + " | " + keap_details["name"]
    new_integration["status"] = "OK"

    now = datetime.utcnow()
    new_integration["created_at"] = now
    new_integration["updated_at"] = now
    new_integration["status_last_check"] = now

    # Create a new integration object
    get_db().create_integration(new_integration)

    return redirect(url_for("main.integrations"))
