from oic.oic import Client as OIDCClient
from oic.oic.message import AuthorizationResponse, IdToken, Message
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

try:
    from oic.oauth2 import rndstr
except ImportError:
    import string
    import random

    def rndstr(size=16):
        """
        Returns a string of random ascii characters or digits
        :param size: The length of the string
        :return: string
        """
        _basech = string.ascii_letters + string.digits
        return "".join([random.choice(_basech) for _ in range(size)])

class Client(object):
    # TODO specify the correct URL
    ISSUER = "https://op-fdqn/"
    flow = 'code'
    scope = ['openid', 'profile', 'email']

    def _get_response_type_for_auth(self):
        if self.flow == 'code':
            return 'code'
        elif self.flow == 'implicit':
            return ["id_token", "token"]
        else:
            return None

    def _get_redirect_uris_for_auth(self):
        if self.flow == 'code':
            return self.client.redirect_uris[0]
        elif self.flow == 'implicit':
            return self.client.redirect_uris[1]
        else:
            return None

    def __init__(self, client_metadata):
        self.flow = 'code'
        self.client = OIDCClient(client_authn_method=CLIENT_AUTHN_METHOD)

        # TODO get the provider configuration information

        # TODO register with the provider using the client_metadata

        # TODO check registration response

    def authenticate(self, session):
        # Use the session object to store state between requests

        # TODO make authentication request
        login_url = obtain_it_from_authorization_request
        return login_url

    def code_flow_callback(self, auth_response, session):
        # TODO parse the authentication response

        # TODO make token request

        # TODO validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)

        # TODO make userinfo request

        # TODO set the appropriate values
        access_code = ''
        access_token = ''
        id_token_claims = ''
        userinfo = ''

        return {
            'auth_code': access_code,
            'access_token': access_token,
            'id_token_claims': id_token_claims,
            'userinfo': userinfo
        }

    def implicit_flow_callback(self, auth_response, session):
        # TODO parse the authentication response

        # TODO validate the ID Token according to the OpenID Connect spec (sec 3.2.2.11.)

        # TODO make userinfo request

        # TODO set the appropriate values
        access_code = ''
        access_token = ''
        id_token_claims = ''
        userinfo = ''

        return {
            'auth_code': access_code,
            'access_token': access_token,
            'id_token_claims': id_token_claims,
            'userinfo': userinfo
        }
