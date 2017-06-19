import random, hashlib, urllib, requests, json, pprint
from oauth2client import app
from flask import render_template, url_for, redirect, session, request, Response

@app.route('/')
def index():
    state = hashlib.sha256(str(random.random())).hexdigest()
    session['state'] = state
    client_id = app.config['CLIENT_ID']
    redirect_uri = app.config['REDIRECT_URI']
    scope = app.config['SCOPE']
    as_auth_url = app.config['AS_AUTH_URL']

    full_as_auth_url_print = '%s\n?response_type=code\n&client_id=%s\n&redirect_uri=%s\n&state=%s\n&scope=%s' % (
        as_auth_url,
        client_id,
        urllib.quote_plus(redirect_uri),
        state,
        scope
    )

    full_as_auth_url = '%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=%s' % (
        as_auth_url,
        client_id,
        urllib.quote_plus(redirect_uri),
        state,
        scope
    )
    
    return render_template(
        'index.html',
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        scope=scope,
        as_auth_url=as_auth_url,
        full_as_auth_url=full_as_auth_url
    )
    

@app.route('/cb')
def cb():
    req = pprint.pformat(request.environ, depth=5)
    code = request.args.get('code')
    session['code'] = code
    state = request.args.get('state')
    if state != session['state']:
        return redirect(url_for('errors'), msg='State mismatch!')

    client_id = app.config['CLIENT_ID']
    client_secret = app.config['CLIENT_SECRET']
    redirect_uri = app.config['REDIRECT_URI']
    as_token_url = app.config['AS_TOKEN_URL']

    return render_template(
        'cb.html',
        code=code,
        state=state,
        client_id = client_id,
        client_secret = client_secret,
        redirect_uri=redirect_uri,
        as_token_url=as_token_url,
        req=req
    )

@app.route('/access_token')
def access_token():
    code = session['code']
    state = session['state']
    client_id = app.config['CLIENT_ID']
    client_secret = app.config['CLIENT_SECRET']
    redirect_uri = app.config['REDIRECT_URI']
    as_token_url = app.config['AS_TOKEN_URL']
    rs_api_url = app.config['RS_API_URL']
    
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'state': state,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri
    }

    headers = {'accept': 'application/json'}
    
    r = requests.post(as_token_url, headers=headers, data=payload)

    raw_response = r.text
    access_token=r.json()['access_token']
    scope=r.json()['scope']
    token_type=r.json()['token_type']

    session['access_token'] = access_token
    
    return render_template(
        'access_token.html',
        raw_response=r.text,
        rs_api_url=rs_api_url,
        access_token=access_token,
        scope=scope,
        token_type=token_type
    )

@app.route('/user_info')
def resource():
    rs_api_url = app.config['RS_API_URL']
    access_token = session['access_token']
    
    headers = {'Authorization': 'Bearer '+access_token}
    
    r = requests.get(rs_api_url+'user', headers=headers)

    return Response(r.text, mimetype='application/json')
    

@app.route('/errors')
def errors():
    msg = request.args.get('msg')
    print msg
