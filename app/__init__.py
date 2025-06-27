from flask import Flask
from flask_cors import CORS
from flask_session import Session
from .api import bp_api
from .auth import bp_auth
from dotenv import load_dotenv
import os
load_dotenv()

origins_str = os.getenv('CORS_ORIGINS')
ORIGINS_LIST = origins_str.split(',')
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')

# origins = ['http://localhost:3000']
def create_app():
   app = Flask(__name__)
   CORS(app, supports_credentials=True, origins=ORIGINS_LIST)
   app.secret_key = APP_SECRET_KEY


   app.register_blueprint(bp_api)
   app.register_blueprint(bp_auth)
   return app