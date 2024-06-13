# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

# session id protection

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash, make_response
from flask_mysqldb import MySQL
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

import yaml
import re
import argon2
import pyotp
import secrets, string
import sys
import unicodedata
import requests
import json


class InvalidOTPError(Exception):
    pass


app = Flask(__name__)
# Configure rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = secrets.token_hex()
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Configure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

csrf = CSRFProtect(app)

# Initialize the Flask-Session
Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
   
    if session['recovery_keys_num'] == 0:
        new_recovery_keys = generate_recovery_keys()
        new_str_recovery_keys = str(','.join(i for i in new_recovery_keys))
        new_hashed_recovery_keys = hash_recovery_key(new_recovery_keys)
        new_str_hashed_recovery_keys = str(';'.join(i for i in new_hashed_recovery_keys))
        update_recovery_key(session['username'], new_str_hashed_recovery_keys)
        session['recovery_keys_num'] = len(new_recovery_keys)
        return render_template('rebind_recovery_keys.html', recovery_keys=new_recovery_keys, str_recovery_key=new_str_recovery_keys)

    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_messages')
@limiter.exempt
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text,message_type, message_value, message_iv, message_tag, created_at
     FROM messages 
                   WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})

@app.route('/rebind_otp')
def rebind_otp():
    # get username
    username = session.get('username')
    # generate TOTP secret
    totp_secret = pyotp.random_base32()
    # generate QRCode url
    auth = pyotp.totp.TOTP(totp_secret, digits=8).provisioning_uri(name=username, issuer_name="COMP3334 Group 12")

    # generate recovery keys
    recovery_keys = generate_recovery_keys()
    str_recovery_keys = str(','.join(i for i in recovery_keys))
    hashed_recovery_keys = hash_recovery_key(recovery_keys)
    str_hashed_recovery_keys = str(';'.join(i for i in hashed_recovery_keys))

    update_recovery_key(username, str_hashed_recovery_keys)
    update_totp_secret(username, totp_secret)
    return render_template('bind_otp.html', auth=auth, recovery_keys=recovery_keys, str_recovery_key=str_recovery_keys)



@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        userDetails = request.form
        # Get the username and password
        username = userDetails['username']
        # Normalize unicode string
        password = unicodedata.normalize('NFKC', userDetails['password'])

        # Retrieve captcha token
        cap_token = userDetails['h-captcha-response']
        # Configure parameters for capcha verify
        params = {
            "secret": "ES_e15647aa740f4ed98c1fa7c3415c670d",
            "response": cap_token,
        }
        # Send post request to hcaptcha api for verification
        cap_json = requests.post('https://hcaptcha.com/siteverify', data=params)
        # parse the json response
        cap_response = json.loads(cap_json.text)
        cap_success = cap_response['success']
        # If captcha verification fails, notify the user
        if not cap_success:
            error = 'Invalid captcha'
            return render_template('register.html', error=error)

        # Check whether the username is existed
        if check_name_existed(username):
            error = "Username is existed"
            return render_template('register.html', error=error)
        else:
            # initialize an argon2 password hasher
            ph = argon2.PasswordHasher()

            # hash password
            password_hash = ph.hash(password)

            # generate TOTP secret
            totp_secret = pyotp.random_base32()
            # generate QRCode url
            auth = pyotp.totp.TOTP(totp_secret, digits=8).provisioning_uri(name=username, issuer_name="COMP3334 Group 12")

            # generate recovery keys
            recovery_keys = generate_recovery_keys()
            str_recovery_keys = str(','.join(i for i in recovery_keys))
            hashed_recovery_keys = hash_recovery_key(recovery_keys)
            str_hashed_recovery_keys = str(';'.join(i for i in hashed_recovery_keys))


            register_new(username, password_hash, totp_secret, str_hashed_recovery_keys)
            flash('Your account has been created.', 'info')
            return render_template('bind_otp.html', auth=auth, recovery_keys=recovery_keys, str_recovery_key=str_recovery_keys)

    return render_template('register.html', error=error)

 # randomly generate recovery keys securely
def generate_recovery_keys():
    keys = []
    for i in range(6): # 6 recovery keys
        key = ''
        for j in range(8): # 8 digits
            key += str(''.join(secrets.choice(string.ascii_letters)))
        keys.append(key)
    return keys

def hash_recovery_key(keys):
    hashed_recovery_keys = []
    ph = argon2.PasswordHasher()
    for k in keys:
        hashed_recovery_keys.append(ph.hash(k))
    return hashed_recovery_keys

def check_name_existed(username):
    # Connect to the database
    cur = mysql.connection.cursor()

    # Use sql to check whether there is same username in the database
    cur.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
    search_result = cur.fetchone()[0]
    number_of_existing = int(search_result)

    # Check whether the number of username is more than 0
    if number_of_existing > 0:
        # Already existing
        return True
    else:
        # Not existing
        return False

def register_new(username, password, totp_secret, recovery_keys):
    # Connect to the database
    cur = mysql.connection.cursor()

    # Use sql to input the new username and the password
    cur.execute("INSERT INTO users (username, password, totp_secret, recovery_keys) VALUES (%s, %s, %s, %s)", (username, password, totp_secret, recovery_keys))

    # Commit the operation to save the change
    mysql.connection.commit()

    return

def update_password(username, password_hash):
    cur = mysql.connection.cursor()

    cur.execute("UPDATE users SET password = %s WHERE username = %s", (password_hash, username))

    mysql.connection.commit()

    return


def verify_recovery_key(hashed_recovery_keys, key):
    ph = argon2.PasswordHasher()
    for h in hashed_recovery_keys:
        try:
            print(h, file=sys.stdout)
            ph.verify(h, key)
            return True, h
        except argon2.exceptions.VerifyMismatchError:
            continue
    return False, '0'

def update_recovery_key(username, str_recovery_keys):
    cur = mysql.connection.cursor()

    cur.execute("UPDATE users SET recovery_keys = %s WHERE username = %s", (str_recovery_keys, username))

    mysql.connection.commit()

    return

def update_totp_secret(username, totp_secret):
    cur = mysql.connection.cursor()

    cur.execute("UPDATE users SET totp_secret = %s WHERE username = %s", (totp_secret, username))

    mysql.connection.commit()

    return


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('100 per day')
def login():
    error = None
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = unicodedata.normalize('NFKC', userDetails['password'])
        otp = userDetails['otp']
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, password, totp_secret, recovery_keys FROM users WHERE username=%s", [username])
        account = cur.fetchone()
        if account:
            password_hash = account[1]
            ph = argon2.PasswordHasher()

            # Retrieve captcha token
            cap_token = userDetails['h-captcha-response']
            # Configure parameters for capcha verify
            params = {
                "secret": "ES_e15647aa740f4ed98c1fa7c3415c670d",
                "response": cap_token,
            }
            # Send post request to hcaptcha api for verification
            cap_json = requests.post('https://hcaptcha.com/siteverify', data=params)
            # parse the json response
            cap_response = json.loads(cap_json.text)
            print(cap_response, file=sys.stdout)
            cap_success = cap_response['success']
            # If captcha verification fails, notify the user
            if not cap_success:
                error = 'Invalid captcha'
                return render_template('login.html', error=error)

            try:
                # verify password
                ph.verify(password_hash, password)

                # get user's totp secret
                totp_secret = account[2]
                totp = pyotp.TOTP(totp_secret, digits=8)

                # get user's recovery keys
                str_hashed_recovery_keys = account[3]
                hashed_recovery_keys = str_hashed_recovery_keys.split(';')
                # verify totp
                if totp.verify(otp):
                    session['username'] = username
                    session['user_id'] = account[0]
                    session['recovery_keys_num'] = len(hashed_recovery_keys)
                    # resp = make_response(render_template('chat.html', sender_id=session['user_id']))
                    resp = make_response(redirect(url_for('index')))
                    resp.set_cookie('username', value=username, max_age=600, secure=True, httponly=True, samesite='strict')
                    return resp
                # verify recovery keys
                rk_valid, h = verify_recovery_key(hashed_recovery_keys, otp)
                if rk_valid:
                    # remove the used recovery key
                    hashed_recovery_keys.remove(h)

                    # update recovery key
                    update_recovery_key(username, str(';'.join(k for k in hashed_recovery_keys)))
                    session['username'] = username
                    session['user_id'] = account[0]
                    session['recovery_keys_num'] = len(hashed_recovery_keys)
                    # resp = make_response(render_template('chat.html', sender_id=session['user_id']))
                    resp = make_response(redirect(url_for('index')))
                    resp.set_cookie('username', value=username, max_age=600, secure=True, httponly=True,
                                    samesite='strict')
                    # check if the password need to be rehashed
                    if ph.check_needs_rehash(password_hash):
                        update_password(username, ph.hash(password))
                    return resp
                else:
                    raise InvalidOTPError

            except argon2.exceptions.VerifyMismatchError:
                error = 'Invalid password.'
            except InvalidOTPError:
                error = 'Invalid OTP.'
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)


@app.route('/send_message', methods=['POST'])
@limiter.exempt
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']
    message_type = request.json['message_type']
    message_iv = request.json['message_iv']
    message_value = request.json['message_value']
    message_tag = request.json['message_tag']

    # Assuming you have a function to save messages
    # if (message_type!="erase chat"):
    save_message(sender_id, receiver_id, message_text, message_type, message_iv, message_value, message_tag)
    # save_message(sender_id, receiver_id, message_text)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message, msg_type, msg_iv, msg_value, msg_tag):
    if (sender<0 or receiver <0):
        return
    elif (msg_type == 'normal'):
        if (msg_value!=''):
            return
        if not re.match("^[0-9,]*$", message):
            return
        if not re.match("^[0-9]*$", msg_iv):
            return
        if not re.match("^[0-9,]*$", msg_tag):
            return
    elif (msg_type == 'ECDH request' or msg_type =='ECDH response'):
        if (msg_iv!='' or msg_value!='' or msg_tag!=''):
            return
        # print(type(message))
        if (not isinstance(message,dict)):
            return
        # try:
        #     json.loads(message.replace("\'","\""))
        # except ValueError as e:
        #     return
    elif (msg_type =='refresh key'):
        if (message!=''):
            return
        if not re.match("^[0-9]*$", msg_iv):
            return
        if not re.match("^[0-9,]*$", msg_tag):
            return
        if not re.match("^[0-9,]*$", msg_value):
            return
    elif (msg_type=='erase chat'):
        if (message!='' or msg_iv or msg_tag or msg_value):
            return
    else:
        return   

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text, message_type, message_iv, message_value, message_tag) VALUES (%s, %s, %s, %s,%s,%s, %s)", (sender, receiver, message, msg_type,msg_iv, msg_value, msg_tag))
    # cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (%s, %s, %s)", (sender, receiver, message))

    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
@limiter.exempt
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('rate_limit_exceeded.html'), 429

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

if __name__ == '__main__':
    app.run(debug=True)

