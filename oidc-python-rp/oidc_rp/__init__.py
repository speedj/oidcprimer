import os
import json

from flask import Flask
from flask_bootstrap import Bootstrap
from oidc_rp.client import Client

client_config = {}
with open('../client.json', 'r') as f:
    client_config = json.loads(f.read())

client = Client(client_config)
app = Flask(__name__)

# SECRET_KEY
## Insert your secret key
# To generate a secret key in a python shell:
## >>> import os
## >>> os.urandom(24)
app.secret_key = '\x8c:\x03\xbd\xb6\xa4\r\xa0\xf1+o\x08\xa3OU\x92u\xf4(k\x12\xf9?\xad'

bootstrap = Bootstrap(app)

from oidc_rp import webserver
