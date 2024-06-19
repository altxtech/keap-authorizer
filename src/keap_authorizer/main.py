from flask import Blueprint, request, Flask, render_template, url_for, redirect, session, current_app
from werkzeug.security import generate_password_hash 

import os
import urllib.parse
import json
import requests 
from datetime import datetime, timedelta
from uuid import uuid4
import re

from keap_authorizer.auth import auth
from keap_authorizer.db import get_db
from keap_authorizer.users import check_reset_password

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


@main.route("/integrations")
@auth.login_required
@check_reset_password
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
@check_reset_password
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
@check_reset_password
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

    # Attempt to capture leads. Log warning if it fails
    try:
        _capture_leads(access_token)
    except Exception as e:
        print(f"Failed to capture leads: {e}")

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



def _capture_leads(access_token):

    # Extract users
    h = {'Authorization': 'Bearer ' + access_token}
    users = []

    next = "https://api.infusionsoft.com/crm/rest/v1/users"
    while True:
        r = requests.get(next, headers=h)
        r.raise_for_status()

        new_users = r.json()["users"]
        if len(new_users) == 0:
            break

        users.extend(new_users)
        next = r.json()["next"]

    # Get internal keap credentials
    internal_creds = _get_internal_keap_credentials()
    
    lead_headers = {
        "Authorization": "Bearer " + internal_creds["access_token"],
        "Content-Type": "application/json"
    }

    for user in users:

        new_lead = {
                "given_name": user["given_name"],
                "family_name": user["family_name"],
                "email_address": [
                    {"email": user["email_address"], "field": "EMAIL2"}
                ],
                "source_type": "API"
        }

        r = requests.post("https://api.infusionsoft.com/crm/rest/v2/contacts", headers=lead_headers, json=new_lead)
        r.raise_for_status()

def _get_internal_keap_credentials() -> dict:

    # Fetch current credentials
    internal_creds = get_db().get_internal("keap_credentials")
    if not internal_creds:
        raise Exception("Internal Keap credentials not found")

    # Check if credentials are valid
    expires_at = internal_creds.get("expires_at")
    if not expires_at or datetime.fromisoformat(expires_at) < datetime.utcnow():
        # Refresh token
        form_data = {
            "refresh_token": internal_creds["refresh_token"],
            "grant_type": "refresh_token"
        }
        basic_auth = (current_app.config["KEAP_CLIENT_ID"], current_app.config["KEAP_CLIENT_SECRET"])
        r = requests.post("https://api.infusionsoft.com/token", data=form_data, auth=basic_auth)
        r.raise_for_status()

        response_data = r.json()
        internal_creds["access_token"] = response_data["access_token"]
        internal_creds["refresh_token"] = response_data["refresh_token"]
        internal_creds["expires_at"] = (datetime.utcnow() + timedelta(seconds=response_data["expires_in"])).isoformat()
        get_db().update_internal("keap_credentials", internal_creds)

    return internal_creds

