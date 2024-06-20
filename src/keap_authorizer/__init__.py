import os

from flask import Flask

from keap_authorizer.db import Database

from keap_authorizer.main import main
from keap_authorizer.users import bp as users


def create_app():
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    # Load default config
    app.config.from_object("keap_authorizer.default_config")
    app.config.from_pyfile("config.py", silent=True)

    # Load environemnt specific config
    env = os.environ["ENV"]
    app.config["DATABASE_ID"] = os.environ["DATABASE_ID"].split("/")[-1]

    # Initialize Database
    db = Database(app.config["DATABASE_ID"])
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(main)
    app.register_blueprint(users)


    return app

