from flask import Flask
from flask_cors import CORS
from flask_session import Session
from .api import bp_api
from .auth import bp_auth

origins = ['http://localhost:3000']
def create_app():
   app = Flask(__name__)
   CORS(app, supports_credentials=True, origins=origins)
   app.secret_key = 'asdasdasd'


   app.register_blueprint(bp_api)
   app.register_blueprint(bp_auth)
   return app