import os

from flask import Flask

from keap_authorizer.db import Database

from keap_authorizer.main import main
from keap_authorizer.users import bp as users


def create_app():
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    # Load default config from source control
    app.config.from_object('config.Config')

    # Load environemnt specific config
    env = os.environ["ENV"]
    app.config["DATABASE_ID"] = os.environ["DATABASE_ID"].split("/")[-1]

    if env == "local":
        app.config.from_object('config.LocalConfig')

    elif env == "dev":
        app.config.from_object('config.DevelopmentConfig')

    elif env == "prod":
        app.config.from_object('config.ProductionConfig')

    # Initialize Database
    db = Database(app.config["DATABASE_ID"])
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(main)
    app.register_blueprint(users)


    return app

