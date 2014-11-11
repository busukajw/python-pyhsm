import sys
import re
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, url_for, jsonify, request
from flask.ext.sqlalchemy import SQLAlchemy
sys.path.append('../Lib')
from pyhsm import YHSM
from pyhsm.yubikey import split_id_otp, validate_yubikey_with_aead
from pyhsm.exception import YHSM_Error
from pyhsm.aead_cmd import YHSM_GeneratedAEAD


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/val'
app.config['HSM'] = 'yhsm://localhost:5348'
app.config['KEY_HANDLE'] = '1'
app.config['DEBUG'] = True

# Specify how often the sync daemon awakens
app.config['__YKVAL_SYNC_INTERVAL__'] = 10;
# Specify how long the sync daemon will wait for response
app.config['__YKVAL_SYNC_RESYNC_TIMEOUT__'] = 30;
# Specify how old entries in the database should be considered aborted attempts
app.config['__YKVAL_SYNC_OLD_LIMIT__'] = 10;

# These are settings for the validation server.
app.config['__YKVAL_SYNC_FAST_LEVEL__'] = 1;
app.config['__YKVAL_SYNC_SECURE_LEVEL__'] = 40;
app.config['__YKVAL_SYNC_DEFAULT_LEVEL__'] = 60;
app.config['__YKVAL_SYNC_DEFAULT_TIMEOUT__'] = 1;
app.config['__YKVAL_SYNC_POOL__'] = ['localhost','192.192.1.1']

valid_key_content = re.compile('^[cbdefghijklnrtuv]{32,48}$')

db = SQLAlchemy(app)


class ValidationError(ValueError):
    pass


class Clients(db.Model):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    active = db.Column(db.Boolean, default=True)
    created = db.Column(db.Integer, nullable=False)
    secret = db.Column(db.String(60), nullable=False, default='')
    email = db.Column(db.String(255))
    notes = db.Column(db.String(100), default='')
    otp = db.Column(db.String(100), default='')

    def get_url(self):
        return url_for('get_client', _external=True)


class Yubikeys(db.Model):
    __tablename__ = 'yubikeys'
    active = db.Column(db.Boolean, default=True)
    created = db.Column(db.Integer,  nullable=False)
    yk_publicname = db.Column(db.String(16), unique=True, nullable=False, primary_key=True)
    yk_counter = db.Column(db.Integer, nullable=False)
    yk_use = db.Column(db.Integer, nullable=False)
    yk_low = db.Column(db.Integer, nullable=False)
    yk_high = db.Column(db.Integer, nullable=False)
    nonce = db.Column(db.String(40), default='')
    notes = db.Column(db.String(100), default='')

    def get_url(self):
        return url_for('get_yubikeys', _external=True)


class Queue(db.Model):
    __tablename__ = 'queue'
    queued = db.Column(db.Integer)
    modified = db.Column(db.Integer)
    server_nonce = db.Column(db.String(32))
    otp = db.Column(db.String(100), nullable=False)
    server = db.Column(db.String(100), nullable=False)
    info = db.Column(db.String(256), nullable=False)

    def get_url(self):
        return url_for('get_queue', _external=True)


class Sync():
    """process used to check whether an otp is has already been used or is a new otp.
        The first step is to check the local database if the otp is a replayed otp.  Then try and check
        the remote pool of servers
     """
    def __init__(self, sync_servers):
        self._sync_servers = sync_servers

    def sync_servers(self):
        return self._sync_servers

    def get_client_info(self, client_id):
        client = Clients()
        client_info = client.query.filter_by(id = client_id).first()
        return ()


@app.route('/wsapi/2.0/verify')
def verify():
    """ """
    if not request.method == 'GET':
        app.logger.error('Invalid request method %s', request.method)
        raise ValidationError('Invalid requests method %s', request.method)
    else:
        app.logger.info(request.url)
        #check for required request arguments
        if 'otp' in request.args:
            otp = request.args.otp
        else:
            app.logger.error('Request argument OTP missing')
            raise ValidationError('Request argument OTP missing')
        if 'nonce' in request.args:
            nonce = request.args.nonce
            if not check_nonce(nonce):
                app.logger.error('Invalid nonce')
        else:
            app.logger.error('Request argument nonce missing')
        if 'id' in request.args:
            client_id = request.args.id
        else:
            app.logger.error('Request argument ')
        if 'timeout' in request.args:
            timeout = request.args.timeout
        else:
            app.logger.info('Request argument timeoute missing')
        if 'sl' in request.args:
            sl = check_sl(request.args.sl)
            if sl == 'Error':
                app.logger.error('OTP %s Invalid sync level %s' % (otp, sl))
                raise ValidationError('Invalid sync level %s', sl)
        else:
            app.logger.info('Request argument sl missing')
            sl = app.config['__YKVAL_SYNC_DEFAULT_LEVEL__']
        if 'timestamp' in request.args:
            timestamp = request.args.timestamp
        else:
            app.logger.info('Request argument timeout missing')

def check_sl(sl):
    if sl.lower() == 'fast':
        sl = app.config['__YKVAL_SYNC_FAST_LEVEL__']
    elif sl.lower() == 'secure':
        sl = app.config['__YKVAL_SYNC_SECURE_LEVEL__']
    else sl in range(1, 100):
        sl = sl
    return sl

def check_client_info(client_id, api_key):
    """Given a client_id and an api_key
    :param client_id:
    :return:
    """

def check_nonce(nonce):
    pass
