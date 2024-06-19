
# Default config. Allways loaded
class Config(object):
    HOST = "http://localhost:5000"
    KEAP_CLIENT_ID = ""
    KEAP_CLIENT_SECRET = "" 
    AIRBYTE_API_URL = "http://localhost:8001/api/v1"
    AIRBYTE_USERNAME = "airybte"
    AIRBYTE_PASSWORD = "password"
    AIRBYTE_WORKSPACE_ID = ""
    AIRBYTE_DESTINATION_KEAP_DEFINITION_ID = ""
    ROOT_USERNAME = "root"
    ROOT_PASSWORD = "password"
    INTERNAL_KEAP_ACCESS_TOKEN = ""
    INTERNAL_KEAP_REFRESH_TOKEN = ""

# Environment specific configs. Override default.
class LocalConfig(Config):
    pass

class DevelopmentConfig(Config):
    pass

class ProductionConfig(Config):
    pass
