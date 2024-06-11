from abc import ABC, abstractmethod
import os

def load_config():
    env = os.environ["ENV"]
    if env == "dev" or env == "prod":
        return GCPSecretConfig(os.environ["secret_id"])
    elif env == "local":
        return JsonConfig("config.json")
    else:
        raise Exception("Invalided ENV environment variable")

# I need to stop overcomplicating things...
class AppConfig(ABC):

    '''
    Required Attributes

    # General
    HOST -> url here the app is hosted
    
    # Keap Client
    KEAP_CLIENT_ID
    KEAP_CLIENT_SECRET

    # Keap App
    KEAP_APP_ACCESS_TOKEN
    KEAP_APP_REFRESH_TOKEN
    KEAP_APP_EXPIRES_AT

    # Airbyte
    AIRBYTE_API_URL
    AIRBYTE_WORKSPACE_ID
    AIRBYTE_KEAP_DESTINATION_ID

    '''

    # Interface
    @abstractmethod
    def _load
