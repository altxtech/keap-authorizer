from flask import request, Flask, render_template, url_for, redirect

from wtforms import Form, StringField, SubmitField

import os
import urllib.parse
import json
import requests 


app = Flask(__name__)

# configuration
def load_config() -> dict:
    env = os.environ["ENV"]
    if env == "local":
        with open("config.json", "r") as f:
            return json.load(f)
    return {}

config = load_config()

class NewCustomerForm(Form):
    identifier = StringField('Identifier')
    submit = SubmitField('Create')


def keap_auth_url(state):
    base_url = "https://accounts.infusionsoft.com/app/oauth/authorize" # Can I hardcode this?
    params = {
            "client_id": config["KEAP_CLIENT_ID"],
            "redirect_uri": config["HOST"] + url_for('auth'),
            "scope": "full",
            "response_type": "code",
            "state": state
    }
    return base_url + "?" + urllib.parse.urlencode(params)

@app.route("/")
def hello():
    return render_template("base.html")

@app.route("/newCustomer", methods=['GET','POST'])
def new_customer():
    
    form = NewCustomerForm(request.form)
    if request.method == 'POST' and form.validate():
        
        # Build the state object
        print(form.identifier)

        state_data = {"identifier": form.identifier.data}
        state = json.dumps(state_data)

        # Get the auth urllib
        auth_url = keap_auth_url(state)
        return redirect(auth_url)
        

    return render_template("new_customer.html", form=form)

@app.route("/newCustomer/auth")
def auth():
    print(request.args)

    # Exchange code for access token
    auth_code = request.args["code"]
    state = json.loads(request.args["state"])
    
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

    # Store customer info in the database, capture lead for sg
    # TODO

    # Deploy airbyte destination
    payload = {
            "name": state["identifier"] + "_" + "keap",
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

    return "Integration Successful"
