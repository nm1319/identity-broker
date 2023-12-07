import os
import logging

from flask_appbuilder.security.manager import AUTH_OAUTH

basedir = os.path.abspath(os.path.dirname(__file__))
logger = logging.getLogger(__name__)

GOOGLE_CLIENT_ID = '***please update'
GOOGLE_SECRET = '***please update'
ADMIN_EMAILS = '***please update'

AUTH_TYPE = AUTH_OAUTH
AUTH_ROLE_ADMIN = 'Admin'
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = 'Admin'  # Testing with just everyone as admin

OAUTH_PROVIDERS = [{
'name':'google',
    'token_key':'access_token',
    'icon':'fa-google',
        'remote_app': {
            'api_base_url':'https://www.googleapis.com/oauth2/v2/',
            'client_kwargs':{
                'scope': 'email profile'
            },
            'access_token_url':'https://accounts.google.com/o/oauth2/token',
            'authorize_url':'https://accounts.google.com/o/oauth2/auth',
            'request_token_url': None,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_SECRET,
        }
}]

# Custom Security Manager in order to get around the `role_keys` missing from Google OAuth response
# See: https://github.com/apache/airflow/issues/16783
from airflow.www.security import AirflowSecurityManager
AUTH_ROLES_MAPPING = {
    "devs": ["Viewer"],
    "admins": ["Admin"]
}

class GoogleAirflowSecurityManager(AirflowSecurityManager):
    def oauth_user_info(self, provider, resp):
        assert provider == "google", "Google provider is only supported in this Security Manager"
        me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo")
        data = me.json()
        email = data.get("email", "")
        # Maps back to AUTH_ROLES_MAPPING keys
        role_keys = ["admins"] if email in ADMIN_EMAILS else ["devs"]
        return {
            "username": "google_" + data.get("id", ""),
            "first_name": data.get("given_name", ""),
            "last_name": data.get("family_name", ""),
            "email": email,
            "role_keys": role_keys
        }

SECURITY_MANAGER_CLASS = GoogleAirflowSecurityManager