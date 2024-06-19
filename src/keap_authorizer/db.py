from typing import Optional, Any
from flask import current_app, g
from google.cloud import firestore
from werkzeug.security import generate_password_hash


class Database():
    def __init__(self, database_id: Optional[str] = None):
        self.db = firestore.Client(database = database_id)
        self.users_ref = self.db.collection("users")
        self.integrations_ref = self.db.collection("integrations")
        self.internal_ref = self.db.collection("internal") # Internal use only 

    def init_app(self, app):
        
        # Set root user
        root_user = self.get_user("root")
        if root_user is None:

            root_username = app.config["ROOT_USERNAME"]
            print("Root username: ", root_username)
            root_password = app.config["ROOT_PASSWORD"]
            root_user = {
                "username": root_username,
                "password": generate_password_hash(root_password),
                "roles": ["admin"]
            }
            self.create_user(root_user)

        # OAuth2 credentials for the internal Keap App
        keap_credentials = self.get_internal("keap_credentials")
        if keap_credentials is None:
            self.create_internal("keap_credentials", {
                "access_token": app.config["INTERNAL_KEAP_ACCESS_TOKEN"],
                "refresh_token": app.config["INTERNAL_KEAP_REFRESH_TOKEN"]
            })

        # Set app config
        app.config["DB"] = self
    
    # Users
    def create_user(self, user: dict) -> None:
        self.users_ref.document(user["username"]).set(user)

    def get_user(self, username: str) -> dict[str, Any] | None:
        user = self.users_ref.document(username).get()
        if user.exists:
            return user.to_dict()
        return None

    def get_all_users(self) -> list:
        return [user.to_dict() for user in self.users_ref.stream()]

    def update_user(self, username: str, updates: dict) -> None:
        self.users_ref.document(username).update(updates)

    def delete_user(self, username: str) -> None:
        self.users_ref.document(username).delete()

    # Integrations
    def create_integration(self, integration: dict) -> None:
        self.integrations_ref.document(integration["name"]).set(integration)

    def get_all_integrations(self) -> list:
        return [doc.to_dict() for doc in self.integrations_ref.stream()]

    # internal
    def create_internal(self, id: str, data: dict) -> None:
        self.internal_ref.document(id).set(data)

    def get_internal(self, id: str) -> dict[str, Any] | None:
        doc = self.internal_ref.document(id).get()
        if doc.exists:
            return doc.to_dict()
        return None

    def update_internal(self, id: str, data: dict) -> None:
        self.internal_ref.document(id).update(data)


def get_db() -> Database:
    return current_app.config["DB"]
