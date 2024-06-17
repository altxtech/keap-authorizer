from typing import Optional, Any
from flask import current_app, g
from google.cloud import firestore


class Database():
    def __init__(self, database_id: Optional[str] = None):
        self.db = firestore.Client(database = database_id)
        self.users_ref = self.db.collection("users")
        self.integrations_ref = self.db.collection("integrations")
    
    def create_user(self, user: dict) -> None:
        self.users_ref.document(user["username"]).set(user)

    def get_user(self, username: str) -> dict[str, Any] | None:
        user = self.users_ref.document(username).get()
        if user.exists:
            return user.to_dict()
        return None

    def get_all_users(self) -> list:
        return [user.to_dict() for user in self.users_ref.stream()]

    def create_integration(self, integration: dict) -> None:
        self.integrations_ref.document(integration["name"]).set(integration)

    def get_all_integrations(self) -> list:
        return [doc.to_dict() for doc in self.integrations_ref.stream()]

def get_db() -> Database:
    if 'db' not in g:
        g.db = Database(current_app.config.get("DATABASE_ID"))

    return g.db
