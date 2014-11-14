import sys
import re
import hmac
import logging
from requests import get
from hashlib import sha1
from datetime import datetime
from calendar import timegm
from base64 import b64decode, b64encode
from logging.handlers import RotatingFileHandler

from flask import Flask, url_for, jsonify, request
from flask.ext.sqlalchemy import SQLAlchemy
sys.path.append('../Lib')
from pyhsm.yubikey import split_id_otp



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

    def __init__(self, id, active, created, secret, email, notes, otp):
        self.id = id
        self.active = active
        self.created = created
        self.secret = secret
        self.email = email
        self.notes = notes
        self.otp = otp

    def __repr__(self):
        return '<Clients %r>' % self.id

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
    notes = db.Column(db.String(100), default='', nullable=True)

    def get_url(self):
        return url_for('get_yubikeys', _external=True)

"""    def __init__(self, active, created, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes):
        self.active = active
        self.created = created
        self.yk_publicname = yk_publicname
        self.yk_counter = yk_counter
        self.yk_use = yk_use
        self.yk_low = yk_low
        self.yk_high = yk_high
        self.nonce = nonce

    def __repr__(self):
        return '<Yubikeys %r>' % self.yk_publicname
"""

class Queue(db.Model):
    __tablename__ = 'queue'
    id = db.Column(db.Integer, primary_key=True)
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
        client_info = client.query.filter_by(id=client_id).first()
        return ()

@app.errorhandler(ValidationError)
def bad_request(e):
    response = jsonify({'status': 400, 'error': 'bad request',
                        'message': e.args[0]})
    response.status_code = 400
    return response


@app.route('/wsapi/2.0/verify')
def verify():
    """ """
    if not request.method == 'GET':
        app.logger.error('Invalid request method %s', request.method)
        raise ValidationError('Invalid requests method %s', request.method)
    else:
        otp_result = {}
        app.logger.info(request.url)
        #check for required request arguments
        v_args = check_parms(request)
        if 'error' not in v_args:
            #call remote ksm and check for valid otp
            otp_result = lookup_otp(v_args['otp'],'127.0.0.1:5001')
            if not otp_result['result'] == 'OK':
                raise ValidationError('OTP lookup ERROR %s' % (otp_result['message']))
            else:
                public_id, otp = split_id_otp(v_args['otp'])
                local_sync_info = get_local_sync_record(public_id,otp)
                request_sync_info = otp_result
                request_sync_info['nonce'] = v_args['nonce']
                request_sync_info['public_id'] = public_id
                app.logger.debug('local sync info %s' % local_sync_info)
                if local_sync_info is None:
                    insert_lsyncdb(otp_result)
        else:
            otp_result['Error'] = 'True'
    return jsonify(otp_result), 200, {'Location': request.path}


def insert_lsyncdb(sync_info):
    """
    Take a hash with publicid,nonce and otp sync counters and either add a new record or update
    the existing record
    :param sync_info: has containing all the info that is required for syncing
    :return: success on a successful local syncdb update
    """
    app.logger.debug(type(sync_info['low']))
    yubikey = Yubikeys(yk_counter=sync_info['counter'],
                       created=create_timestamp(),
                       yk_publicname=sync_info['public_id'],
                       nonce=sync_info['nonce'],
                       yk_high=sync_info['high'],
                       yk_low=sync_info['low'],
                       yk_use=sync_info['use'],
                       notes='',
                       )
    db.session.add(yubikey)
    if db.session.commit():
        app.logger.info('SYNCDB local updated %s' % (sync_info['public_id']))
    else:
        app.logger.info('SYNCDB local update failed %s' % (sync_info['public_id']))
        raise ValidationError('Unable to update db')
    return True


def get_local_sync_record(public_id, otp):
    """
    lookup the latest sync settings for any given public_id and return a hash of those settings
    :param public_id:
    :param otp:
    :return: a hash public_id: public_id
                    yk_counter: session_counter
                    yk_use: session_use
                    yk_high: high
                    yk_low: low
                    nonce: nonce
                    otp: otp

    """
    yubikey = Yubikeys.query.filter_by(yk_publicname=public_id).first()
    if yubikey is None:
        pass
    else:
        return {'public_id': public_id,
                'yk_counter': yubikey.yk_counter,
                'yk_use': yubikey.yk_use,
                'yk_high': yubikey.yk_high,
                'yk_low': yubikey.yk_low,
                'nonce': yubikey.nonce}


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
    app.logger.info('in lookup_otp')
    url = 'http://localhost:5001/wsapi/decrypt'
    r = get(url, params=payload)
    print r.json()
    return r.json()

def check_nonce(nonce):
    """
    Make sure that the nonce (random string) has not been used before to make sure that
    :param nonce:
    :return true or false:
    """
    pass


def check_parms(request):
    """
    Check the parameters to make sure that all parameters are correct
    :param params:
    :return:
    """
    req_opts = {}
    app.logger.info('URL arguments %s', request.args)
    try:
        req_opts['otp'] = request.args.get('otp')
        if not valid_key_content.match(req_opts['otp']):
            raise ValidationError('Invalid OTP')
            app.logger.debug('WOW that was apparently valid')
    except AttributeError:
        app.logger.error('Request argument OTP missing')
        raise ValidationError('Required argument OTP missing')
    try:
        req_opts['nonce'] = request.args['nonce']
    except KeyError:
        app.logger.error('Request argument nonce missing')
        req_opts['error'] = 'nonce'
        raise ValidationError('required argument nonce missing')
    try:
        req_opts['id'] = request.args['id']
    except KeyError:
        app.logger.error('required argument id missing')
        raise ValidationError('required argument id missing')
    if 'timeout' in request.args:
        req_opts['timeout'] = request.args.timeout
    else:
        app.logger.info('Request argument timeoute missing')
    if 'sl' in request.args:
        req_opts['sl'] = check_sl(request.args.sl)
        if req_opts['sl'] == 'Error':
            app.logger.error('OTP %s Invalid sync level %s' % (req_opts['otp'], req_opts['sl']))
        else:
            app.logger.info('Request argument sl missing')
            sl = app.config['__YKVAL_SYNC_DEFAULT_LEVEL__']
    if 'timestamp' in request.args:
        req_opts['timestamp'] = request.args.timestamp
    else:
        app.logger.info('Request argument timestamp missing')
    return req_opts


def create_timestamp():
    """
    Create a unix timestamp from the current utc time
    :return unix timestampas in int
    """
    d = datetime.utcnow()
    return timegm(d.utctimetuple())

if __name__ == '__main__':
    db.create_all()
    handler = RotatingFileHandler('val_server.log')
    handler.setLevel(logging.DEBUG)
    app.logger.addHandler(handler)
    app.run()