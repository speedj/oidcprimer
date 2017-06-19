# OAuth2 Course - Simple Client

This very simple OAuth2 client implements the OAuth2 Authorization Code Grant, showing each HTTP request/response between the Client, the Authentication Server, and
finally the Resource Server. It can be freely used in courses about OAuth2.

## How to run

In order to use this simple client, open config.py and setup:
- a SECRET_KEY (see instruction in config.py)
- an Authentication Server Authorization URL in AS_AUTH_URL (or uncomment the Github one)
- an Authentication Server Tokent URL (or uncomment the Github one)
- a Resource Server API URL (or uncomment the Github one)
- OAuth2 CLIENT_ID and CLIENT_SECRET (provided by your Authentication Server)
- the OAuth2 Client REDIRECT_URI, composed by your base URL + ':9000/cb'

## Virtualenv
We strongly reccomend to use virtualenv to set up the python environment to run the Flask app:

```
virtualenv venv
```
Activate the virtualenv
```
. venv/bin/activate
```
With the venv activated, install all the required python modules
```
pip install -r requirements.txt
```

Once everything is set up you can run the Flask app:

```
python run.py
```

Enjoy!
