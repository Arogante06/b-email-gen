from flask import Blueprint, session, jsonify, request
import requests, os, logging
from dotenv import load_dotenv
import base64
from email.mime.text import MIMEText
from typing import TypedDict
load_dotenv()

logging.basicConfig(level=logging.INFO)

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

bp_api = Blueprint('api', __name__, url_prefix='/api/v1')

@bp_api.route("/emails", methods=["GET", "POST"])
def list_emails():
    
   creds = session.get('credentials')
   if not creds:
      logging.error('No existen creds para esta peticion')
      return jsonify({'error': 'No autenticado'}), 401

   if request.method == "POST":
      to = request.json.get('to')
      subject = request.json.get('subject')
      body = request.json.get('content')
      if not all([to, subject, body]):
         return jsonify({'message': 'Se den prporcionar las 3 partes basicas del correo'}), 400
      res = send_email(creds['token'], to, subject , body)
      if not  res['success']:
         return jsonify({'message': 'No se pudo enviar el correo'}), 500
      return jsonify({'message': 'Correo enviado exitosamente'}), 200
   # print('CREDENTIALS: ', creds)
   headers = {
      'Authorization': f"Bearer {creds['token']}"
   }

   # Obtener últimos 10 correos
   params = {
      'maxResults': 6,
      'labelIds': 'INBOX'
   }

   gmail_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages'
   r = requests.get(gmail_url, headers=headers, params=params)

   if r.status_code == 401:
      logging.warning('Acceso posiblemente expirado,  intentando refrescar...')
      token = refresh_token(creds['refresh_token'])
      if not token :
         logging.warning('No se pudo refrecar el token')
         return jsonify({'error': 'No se puedo obtner un nuevo token'}), 400
      session['credentials']['token'] = token
      headers['Authorization'] = f"Bearer {token}"

      # Reintentar la petición
      r = requests.get(gmail_url, headers=headers, params=params)

   elif r.status_code != 200:
      logging.error('Error en get ids mails', exc_info=True)
      return jsonify({'error': 'No se pudieron obtener los correos'}), 500

   data = r.json()
   logging.info('Data de ids de los mensajes: %s', data)
   emails , success, message = get_mails_complete(data['messages'], creds)
   return jsonify({'message': message, 'emails': emails, 'success': success}), 200


def get_mails_complete(emails_id: list, creds: dict):
   headers = {
      'Authorization': f"Bearer {creds['token']}"
   }
   params = {'format': 'full'}
   emails = []
   success = True
   message = ''

   try:
      for email in emails_id:
         message_id = email.get('id')
         if not message_id:
               continue

         url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}'
         r = requests.get(url, headers=headers, params=params)

         if r.status_code != 200:
               logging.warning(f"Fallo al obtener mensaje {message_id}: {r.status_code}")
               continue

         parsed = parse_gmail_message(r.json())
         emails.append(parsed)

   except Exception as e:
      success = False
      message = str(e)
      logging.error('Error en la petición de mensajes completos: %s', message)

   return emails, success, message


@bp_api.route('/mail/<string:message_id>')
def get_message(message_id):
   creds = session.get('credentials')
   if not creds:
      return jsonify({'message', 'Not authorized'}), 401
   
   headers = {
      'Authorization': f"Bearer {creds['token']}"
   }

   url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}'
   params = {'format': 'full'} #metadata, full, raw

   r = requests.get(url, headers=headers ,params=params)
   if r.status_code != 200:
      print('Error al obtener correo: ', r.json())
      print(' ██ Attempting refresh token...')
      new_token = refresh_token(creds['refresh_token'])
      creds = session.get('credentials')
      headers['Authorization'] = f'Bearer {creds['token']}' 
      res = requests.get(url, headers=headers, params=params)
      if res.status_code != 200:
         return jsonify({'message': 'No se pudo refrescar el token'}), 400  
      return jsonify(parse_gmail_message(res.json())), 200
   
   return jsonify(parse_gmail_message(res.json())), 200

@bp_api.route('/refresh-token', methods=['GET'])
def refresh():
   refresh_token = request.json.get('token')
   print('Token refresh calling...')
   data = {
      'client_id': GOOGLE_CLIENT_ID,
      'client_secret': GOOGLE_CLIENT_SECRET,
      'refresh_token': refresh_token,
      'grant_type': 'refresh_token',
   }
   r = requests.post('https://oauth2.googleapis.com/token', data=data)
   return r.json()

def refresh_token(refresh_token):
   data = {
   'client_id': GOOGLE_CLIENT_ID,
   'client_secret': GOOGLE_CLIENT_SECRET,
   'refresh_token': refresh_token,
   'grant_type': 'refresh_token',
   }
   r = requests.post('https://oauth2.googleapis.com/token', data=data)
   if r.status_code == 200:
      token_data = r.json()
      session['credentials']['token'] = token_data['access_token']
      return token_data['access_token']
   else:
      print('Error al intentar refrescar el token: ', r.json())
      return None
   
def parse_gmail_message(message_json):
   headers = message_json.get("payload", {}).get("headers", [])
   
   def get_header(name):
      for h in headers:
         if h["name"].lower() == name.lower():
               return h["value"]
      return None

   id_ = message_json.get("id")
   date = get_header("date")
   subject = get_header("Subject")
   sender = get_header("From")
   to = get_header("To")
   labels = message_json.get("labelIds")

   # Extraer cuerpo en texto plano (puede venir en partes)
   def get_body(payload):
      if 'parts' in payload:
         for part in payload['parts']:
               if part['mimeType'] == 'text/plain':
                  data = part['body'].get('data')
                  if data:
                     import base64
                     return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
      elif payload['mimeType'] == 'text/plain':
         data = payload['body'].get('data')
         if data:
               import base64
               return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
      return "Cuerpo no disponible"

   body = get_body(message_json.get('payload', {}))

   return {
      "id": id_,
      "subject": subject,
      "from": sender,
      "to": to,
      "body": body,
      "labels": labels,
      "isImportant": True,
      "isRead": False,
      "date": date
   }

class ResponseProps(TypedDict):
   success: bool
   message: str
   error: object
   data: object
def send_email(token, to, subject, body)->ResponseProps:
   message = MIMEText(body, 'html') #html segundo parametro
   message['to'] = to
   message['subject'] = subject
   raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
   url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send'
   headers = { 'Authorization': f'Bearer {token}', 'Content-Type': 'application/json' }
   response = requests.post(
      url,
      headers=headers,
      json={'raw': raw}
   )
   if response.status_code == 401:
      new_token = refresh_token(session['credentials']['refresh_token'])
      if not new_token:
         return {'success': False, 'message': 'No se pudo refrescar el toke  para enviar el correo', 'error': response.json()}
      session['credentials']['token'] = new_token
      headers['Authorization'] = f'Bearer {new_token}'
      res = requests.post(url, headers=headers, json={'raw': raw} )
      if res.status_code != 200:
         return {'success': False, 'message': 'No se puedo envair el correo', 'error': response.json()}
      return {'success': True, 'message': 'Correo enviado exitosamente', 'data': response.json()}
   elif response.status_code != 200:
      return {'success': False, 'message': 'Error desconocido al intentar enviar el correo', 'error': response.json()}
   logging.warning('DEPURACION AL SEND: %s', response.json())
   return {'success': True, 'message': 'Mensaje enviado correctamente', 'data': response.json()}