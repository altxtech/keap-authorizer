from flask import request, Flask, render_template, url_for, redirect

import os
import urllib.parse
import json
import requests 
from datetime import datetime

from google.cloud import secretmanager, firestore


app = Flask(__name__)
db = firestore.Client(database = os.environ["DATABASE_ID"].split("/")[-1])
integrations_ref = db.collection("integrations")

# configuration
def get_secret(secret_id, version_id="latest"):
    '''
    Return string value of secret
    '''
    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()
    # Build the resource name of the secret version.
    name = f"{secret_id}/versions/{version_id}"
    # Access the secret version.
    response = client.access_secret_version(name=name)
    # Return the decoded payload.
    return response.payload.data.decode("UTF-8")

def load_config() -> dict:
    secret_id = os.environ["SECRET_ID"]
    secret_content = get_secret(secret_id) 
    return json.loads(secret_content)
    
config = load_config()
print(f"Config: {config}")

def keap_auth_url():

    base_url = "https://accounts.infusionsoft.com/app/oauth/authorize" # Can I hardcode this?
    params = {
            "client_id": config["KEAP_CLIENT_ID"],
            "redirect_uri": config["HOST"] + url_for('auth'),
            "scope": "full",
            "response_type": "code"
    }
    return base_url + "?" + urllib.parse.urlencode(params)

@app.route("/")
def hello():
    return render_template("base.html")

@app.route("/integrations", methods=['GET','POST'])
def integrations():

    all_integrations = [doc.to_dict() for doc in integrations_ref.stream()]

    return render_template("integrations.html", integrations = all_integrations, auth_url = keap_auth_url())

@app.route("/integrations/auth")
def auth():
    print(request.args)

    # Exchange code for access token
    auth_code = request.args["code"]
    
    form_data = {
            "client_id": config["KEAP_CLIENT_ID"],
            "client_secret": config["KEAP_CLIENT_SECRET"],
            "code": auth_code,
            "grant_type": "authorization_code",
            "redirect_uri": config["HOST"] + url_for('auth')
    }
    r = requests.post("https://api.infusionsoft.com/token", data=form_data)
    scope = r.json()["scope"]
    keap_app_id = scope.split("|")[1].split(".")[0]
    access_token = r.json()["access_token"]
    refresh_token = r.json()["refresh_token"]

    # Research business profile
    h = {"Authorization": "Bearer " + access_token}
    r = requests.get("https://api.infusionsoft.com/crm/rest/v2/businessProfile", headers = h)
    r.raise_for_status()

    # Store customer info in the database, capture lead for sg
    profile = r.json()
    print(profile)
    new_integration = {
            "created_at": datetime.utcnow(),
            "app_id": keap_app_id,
            "name": profile["name"],
            "email": profile["email"]
    }
    integrations_ref.document().set(new_integration)
    

    # Deploy airbyte destination
    payload = {
            "name": keap_app_id + "_" + "keap",
            "definitionId": config["AIRBYTE_DESTINATION_KEAP_DEFINITION_ID"],
            "workspaceId": config["AIRBYTE_WORKSPACE_ID"],
            "configuration": {
                "client_id": config["KEAP_CLIENT_ID"],
                "client_secret": config["KEAP_CLIENT_SECRET"],
                "keap_app_id": keap_app_id,
                "access_token": access_token,
                "refresh_token": refresh_token
            }
    }
    r = requests.post(
            config["AIRBYTE_API_URL"] + "/destinations",
            auth=(config["AIRBYTE_USERNAME"], config["AIRBYTE_PASSWORD"]),
            json = payload
    )
    r.raise_for_status()

    return redirect(url_for("integrations"))
