# DEBUG
DEBUG = True
TRAP_BAD_REQUEST_ERRORS = True

# SECRET_KEY
## Insert here your secret key
## To generate a secret key in a python shell:
## >>> import os
## >>> os.urandom(24)
SECRET_KEY = b'V2\xe47\x80\x8d\x15\x8e05\x93\xe0\xfd\xe6H\x1f\xf3\x9b\x12\xac\x9d7\x1d\xf7'

# OAuth2 Authentication Server
## EXAMPLE: Github Authentication Server endpoints
#AS_AUTH_URL = 'https://github.com/login/oauth/authorize'
#AS_TOKEN_URL = 'https://github.com/login/oauth/access_token'

AS_AUTH_URL = 'https://github.com/login/oauth/authorize'
AS_TOKEN_URL = 'https://github.com/login/oauth/access_token'


# OAuth2 Resource Server
## EXAMPLE: Github Resource Server API endpoint
#RS_API_URL = 'https://api.github.com/'

RS_API_URL = 'https://api.github.com/'

# OAuth2 Client
CLIENT_ID  = '86f162c1ac400be38d19'
CLIENT_SECRET = '0609749d9a93ae7b9772edb2a9d3bef364c15c76'
REDIRECT_URI = 'http://oidc.localdomain:9000/cb'
SCOPE = 'user'

