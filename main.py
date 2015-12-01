#!/usr/bin/env python
"""
A self-service password change script for Samba 4 AD DC and Google Apps.

By: Nick Semenkovich <semenko@alum.mit.edu> https://nick.semenkovich.com

License: MIT

Google auth code derived from Flask-Oauthlib / Bruno Rocha / https://github.com/rochacbruno
"""

from flask import Flask, redirect, render_template, url_for, session, request, Response, jsonify, abort
from flask_oauthlib.client import OAuth
import hashlib
import json
import os
import requests
import sys
import tempfile

app = Flask(__name__, static_url_path='')
app.config.from_pyfile('secrets.cfg') # Add your Google ID & Secret there.

RESTRICTED_DOMAIN = app.config.get('RESTRICTED_DOMAIN') # Require this domain for authentication
SITE_NAME = app.config.get('SITE_NAME')

PASS_MIN_LENGTH = app.config.get('PASS_MIN_LENGTH')
PASS_BAD_WORDS = app.config.get('PASS_BAD_WORDS')

# These users *cannot* have their passwords set.
PROHIBITED_USERS = app.config.get('PROHIBITED_USERS')


### Samba configuration & settings
# Add a specific import for the Python Samba packages
sys.path.append("/usr/local/samba/lib64/python2.7/site-packages/")

from samba.credentials import Credentials
from samba.auth import system_session
from samba.samdb import SamDB

sambaPrivate = "/usr/local/samba/private"
sambaPath = app.config.get('SAMBA_PATH')

####

app.secret_key = 'development'
oauth = OAuth(app)

google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': ['email', 'profile']
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

def current_password_is_correct_on_pdc(username, current_password):
    # Test the user/password combination against local Samba hive.
    # TODO: Implement this.
    f,fname = tempfile.mkstemp()
    try:
        os.write(f, "username = %s\n" % username)
        os.write(f, "password = %s\n" % current_password)
        os.write(f, "domain = dc.univa.com")
        ret = os.system("smbclient //localhost/netlogon -A%s -c 'ls'" %fname)
        #print "Return code", ret
        return ret == 0
    finally:
        os.close(f)

def change_samba_password(username, password):
    # printf "pass\npass\n" | sudo ./smbpasswd -s caroline
    # echo -e 'new_password\nnew_password' | sudo /usr/local/samba/bin/smbpasswd username  # May fail due to constraints
    if username in PROHIBITED_USERS:
        print("ERROR: Prohibited user.")
        return False
    ret = os.system("bash -c 'echo -ne \"%s\n%s\" | sudo /usr/local/samba/bin/smbpasswd %s >/tmp/logs 2>&1'" % (password,password,username) )
    return ret == 0


@app.route('/', methods = ['GET', 'POST'])
def index():
    if 'google_token' in session:
        me = google.get('userinfo')
        try:
            if me.data[u'hd'] != RESTRICTED_DOMAIN or me.data[u'verified_email'] != True:
                session.pop('google_token', None)
                return render_template('error.html', domain=RESTRICTED_DOMAIN, site_name=SITE_NAME,
                                       detailed_errror="Wrong domain name or unverified email.")
        except KeyError:
            session.pop('google_token', None)
            return render_template('_base.html', site_name=SITE_NAME)
        # return jsonify({"data": me.data})
        # , computer_target=app.config.get('COMPUTER_MAP')[str(me.data[u'email'])]

        username = me.data['email'].split('@')[0] # username only from e-mail

        error=None
        ok = None
        # User posted, probably wants to set a password, neat!
        if request.method == "POST":
            #current_password = request.form.get('password')
            new_password = request.form.get('newpass')

            # The user set a username & password. Sanity check time.
            if username in PROHIBITED_USERS:
                error = "You are not authorized to use this service."
            elif new_password is None:
                error = "You left a password empty. Please try again."
            elif len(new_password) == 0:
                error = "You left a password empty. Please try again."
            elif new_password != request.form.get('confirmpass'):
                error = "Your passwords didn't match. Please try again."
            elif len(new_password) < 10:
                error = "Your password was too short. Please enter a longer password."
            elif sum([word in new_password.lower() for word in PASS_BAD_WORDS]) > 0:
                error = "Your new password cannot contain: %s" % (', '.join(PASS_BAD_WORDS))
            #elif not current_password_is_correct_on_pdc(username, current_password):
            #    error = "Your current password was incorrect. Try again."
            else:
                # We've passed sanity testing, let's change the user's password.

                # First, let's set the samba password
                if change_samba_password(username, new_password):
                    print('Successfully changed samba password.')
                    ok = True
                else:
                    # Samba changing failed. Report that.
                    error = "Couldn't change password: samba failure."
                
        # Got a get/post with valid google_token.
        # Maybe there was an error from the POST, or they're just landing at the GET.
        return render_template('authenticated.html',
                               auth_data=me.data,
                               username=username,
                               site_name=SITE_NAME,
                               minlength=PASS_MIN_LENGTH,
                               badwords=PASS_BAD_WORDS,
                               error=error,
                               ok=ok)

    # No google token. Ask the user to log in.
    return render_template('_base.html', site_name=SITE_NAME)

@app.route('/pwchange')
def getrdp():
    if 'google_token' in session:
        me = google.get('userinfo')
        try:
            if me.data[u'hd'] != RESTRICTED_DOMAIN or me.data[u'verified_email'] != True:
                session.pop('google_token', None)
                return redirect(url_for('logout'))
        except KeyError:
            session.pop('google_token', None)
            return render_template('_base.html', site_name=SITE_NAME)

        try:
            target = request.args.get('target')  # TODO: Sanitize this.
            target_hosts = {'hostname': app.config.get('DOMAIN_SECRET'), 'port': app.config.get('PORT_MAP')[target]}
        except KeyError:
            return redirect(url_for('logout'))

        return Response(RDP_FILE_TEMPLATE % target_hosts,
                        mimetype="application/rdp",
                        headers={"Content-Disposition":
                                     "attachment; filename=computer.rdp"})
    return redirect(url_for('logout'))

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
@google.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    #me = google.get('userinfo')
    return redirect(url_for('index'))
    #return jsonify({"data": me.data})


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = hashlib.sha1(os.urandom(64)).hexdigest()
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
else:
    # Secure app in prod
    app.config['SESSION_COOKIE_SECURE'] = True
