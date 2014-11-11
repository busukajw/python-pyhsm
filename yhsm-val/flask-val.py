import sys
import re
import hmac
import logging
from requests import get
from hashlib import sha1
from base64 import b64decode, b64encode
from logging.handlers import RotatingFileHandler
from flask import Flask, url_for, request
from flask.ext.sqlalchemy import SQLAlchemy
sys.path.append('../Lib')



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
        v_args = check_parms(request.args)


def check_sl(sl):
    if sl.lower() == 'fast':
        sl = app.config['__YKVAL_SYNC_FAST_LEVEL__']
    elif sl.lower() == 'secure':
        sl = app.config['__YKVAL_SYNC_SECURE_LEVEL__']
    elif sl in range(1, 100):
        sl = sl
    return sl


def get_api_key(client_id):
    """Given a client id lookup the ID and return the api key and base64 decode it
    args: id:  client id
    returns the raw api key"""
    api_key = Clients.query.filter_by(id=client_id).first()
    return b64decode(api_key)


def verify_sig(orig_sig, gen_sig):
    """
    Verifiy the signature in a response message.  Take the provided signature and compare it against a generated
    signiture
    args:
        orig_sig: this is the original signature as provided by the response message
       gen_sig: signature generated locally from gen_hmac_sig
    :return true or false
    """
    if orig_sig == gen_sig:
        return True
    else:
        return False


def gen_hmac_sig(http_opts, api_key):
    """Generate a signature based on the returned http get options whilst  removing the h option if it is present.
    The dictionary is then sorted alphabetically on the key use HMAC SHA1 to create the signature
    args: key_pairs : a dictionary of key paris
    returns: a bas64encoded string
    """
    sorted_list = [key + '=' + ''.join(http_opts[key])for key in sorted(http_opts.keys()) if key !='h)']
    sig = hmac.new(api_key, '&'.join(sorted_list), sha1)
    return b64encode(sig.digest())


def lookup_otp(otp,keyserver):
    """
    given an otp send a request to the keyserver asking if the otp is valid
    args:
        otp: the otp :-)
        keyserver: the ip address of the keyserver to use to check the otp
    :return:
    """
    payload = {'otp': otp}
    url = '/wsapi/decrypt'
    r = get(url, params=payload)
    print r.text


def check_nonce(nonce):
    """
    Make sure that the nonce (random string) has not been used before to make sure that
    :param nonce:
    :return true or false:
    """
    pass


def check_parms(http_args):
    """
    Check the parameters to make sure that all parameters are correct
    :param params:
    :return:
    """
    req_opts = {}
    if 'otp' in http_args:
        req_opts['otp'] = http_args.otp
    else:
        app.logger.error('Request argument OTP missing')
        raise ValidationError('Request argument OTP missing')
    if 'nonce' in http_args:
        req_opts['nonce'] = http_args.nonce
        if not check_nonce(req_opts['nonce']):
                app.logger.error('Invalid nonce')
        else:
            app.logger.error('Request argument nonce missing')
    if id in request.args:
        req_opts['id'] = http_args.id
    else:
        app.logger.error('Request argument ')
    if 'timeout' in http_args:
        req_opts['timeout'] = request.args.timeout
    else:
        app.logger.info('Request argument timeoute missing')
    if 'sl' in http_args:
        req_opts['sl'] = check_sl(http_args.sl)
        if req_opts['sl'] == 'Error':
            app.logger.error('OTP %s Invalid sync level %s' % (req_opts['otp'], req_opts['sl']))
            raise ValidationError('Invalid sync level %s', req_opts['sl'])
        else:
            app.logger.info('Request argument sl missing')
            sl = app.config['__YKVAL_SYNC_DEFAULT_LEVEL__']
    if 'timestamp' in http_args:
        req_opts['timestamp'] = http_args.timestamp
    else:
        app.logger.info('Request argument timeout missing')
    return  req_opts


if __name__ == '__main__':
    db.create_all()
    handler = RotatingFileHandler('val_server.log')
    handler.setLevel(logging.DEBUG)
    app.logger.addHandler(handler)
    app.run()