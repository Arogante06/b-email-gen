# backend/routes/auth.py
from flask import Blueprint, redirect, session, request, url_for, jsonify, make_response
from google_auth_oauthlib.flow import Flow
import os, requests

bp_auth = Blueprint('auth', __name__, url_prefix='/auth')

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # solo en desarrollo

GOOGLE_CLIENT_ID = '1021973608039-7g17daqorh4iarl0ajmbjj5drp6e3qlj.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
REDIRECT_URI = 'http://localhost:5000/auth/callback'

SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.profile",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send"
]

flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI]
        }
    },
    scopes=SCOPES
)
flow.redirect_uri = REDIRECT_URI


@bp_auth.route("/google")
def auth_google():
   authorization_url, state = flow.authorization_url(
      access_type='offline',
      include_granted_scopes='true',
      prompt='consent'
   )
   session['state'] = state
   return redirect(authorization_url)


@bp_auth.route("/callback", methods=["GET"])
def auth_callback():
   state = session.get('state')
   if not state:
      return jsonify({"error": "Falta el parámetro state en la sesión"}), 400

   try:
      flow = Flow.from_client_config(
         {
            "web": {
               "client_id": GOOGLE_CLIENT_ID,
               "client_secret": GOOGLE_CLIENT_SECRET,
               "auth_uri": "https://accounts.google.com/o/oauth2/auth",
               "token_uri": "https://oauth2.googleapis.com/token",
               "redirect_uris": [REDIRECT_URI]
            }
         },
         scopes=SCOPES,
         state=state
      )
      flow.redirect_uri = REDIRECT_URI

      flow.fetch_token(authorization_response=request.url)

      if not flow.credentials:
         return jsonify({"error": "No credentials returned"}), 400

      creds = flow.credentials

      userinfo_resp = requests.get(
         'https://www.googleapis.com/oauth2/v1/userinfo', 
         params={'alt': 'json'},
         headers={'Authorization': f'Bearer {creds.token}'}
      )

      if userinfo_resp.status_code != 200: 
         return jsonify({'error': 'Error al obtener perfil'}), 400
      
      profile = userinfo_resp.json()
      print('Datos del profile:', profile)
      

      credentials = {
         'token': creds.token,
         'refresh_token': creds.refresh_token,
         'token_uri': creds.token_uri,
         'client_id': creds.client_id,
         'client_secret': creds.client_secret,
         'scopes': creds.scopes
      }
      session['profile'] = profile
      session['credentials'] = credentials
      response = make_response(redirect("http://localhost:3000/dashboard"))
      # response.set_cookie("name", profile['name'], httponly=False, max_age=3600)
      # response.set_cookie("picture", profile['picture'], httponly=False, max_age=36000)
      response.get_json
      return response
   except Exception as e:
      print("Error en callback:", str(e))
      return jsonify({"error": str(e)}), 500


@bp_auth.route("/me")
def me():
   profile = session.get('profile')
   print('PROFILE: ', profile)
   if not profile:
      return jsonify({"error": "No autenticado"}), 401
   return jsonify(profile)

@bp_auth.route("/logout", methods=['POST'])
def logout():
   session.clear()
   response = make_response(jsonify({'message': 'Session cerrada'}), 200)
   response.set_cookie('session', '', expires=0)  # Borra la cookie de sesión
   response.delete_cookie('session')
   return response