from flask import Flask
from flask_bootstrap import Bootstrap

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config.from_object('oauth2client.config')
app.secret_key = app.config['SECRET_KEY']


from oauth2client import views
