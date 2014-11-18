import sys
import re
import hmac
from requests import get
from hashlib import sha1
from datetime import datetime
from calendar import timegm
from base64 import b64decode, b64encode
from flask import jsonify, request, current_app
sys.path.append('../Lib')
from pyhsm.yubikey import split_id_otp

from . import api
from .. import db
from ..exceptions import ValidationError
from ..models import Clients, Yubikeys


valid_key_content = re.compile('^[cbdefghijklnrtuv]{32,48}$')

@api.errorhandler(ValidationError)
def bad_request(e):
    response = jsonify({'status': 400, 'error': 'bad request',
                        'message': e.args[0]})
    response.status_code = 400
    return response


@api.route('/wsapi/2.0/verify')
def verify():
    """ """
    if not request.method == 'GET':
        current_app.error('Invalid request method %s', request.method)
        raise ValidationError('Invalid requests method %s', request.method)
    else:
        otp_result = {}
        current_app.logger.info(request.url)
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
                current_app.logger.debug('local sync info %s' % local_sync_info)
                if local_sync_info is None:
                    insert_lsyncdb(otp_result)
        else:
            otp_result['Error'] = 'True'
    return jsonify(otp_result), 200, {'Location': request.path}


@api.route('/yubikeys/', methods=['GET'])
def get_yubikeys():
    return jsonify({'yubikeys': [yubikey.export_data() for yubikey in Yubikeys.query.all()]})

@api.route('/yubikeys/<public_id>', methods=['GET'])
def get_yubikey(public_id):
    return jsonify(Yubikeys.query.get_or_404(public_id).export_data())

@api.route('/yubikeys/', methods=['PUT'])
def new_yubikey():
    yubikey = Yubikeys()
    yubikey.import_data(request.json)
    db.session.add(yubikey)
    db.session.commit()
    return jsonify({}, 201, {'Location': yubikey.get_url()})

@api.route('/clients/<client_id>', methods=['GET'])
def get_client(client_id):
    return jsonify(Clients.query.get_or_404(client_id).export_data())

def insert_lsyncdb(sync_info):
    """
    Take a hash with publicid,nonce and otp sync counters and either add a new record or update
    the existing record
    :param sync_info: has containing all the info that is required for syncing
    :return: success on a successful local syncdb update
    """
    yubikey = Yubikeys(active=True,
                       yk_counter=sync_info['counter'],
                       created=create_timestamp(),
                       yk_publicname=sync_info['public_id'],
                       nonce=sync_info['nonce'],
                       yk_high=sync_info['high'],
                       yk_low=sync_info['low'],
                       yk_use=sync_info['use'],
                       notes='',
                       )
    db.session.add(yubikey)
    try:
        db.session.commit()
        current_app.logger.info('SYNCDB local updated %s' % (sync_info['public_id']))
    except:
        current_app.logger.info('SYNCDB local update failed %s' % (sync_info['public_id']))
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
        sl = api.config['__YKVAL_SYNC_FAST_LEVEL__']
    elif sl.lower() == 'secure':
        sl = api.config['__YKVAL_SYNC_SECURE_LEVEL__']
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
    current_app.logger.info('in lookup_otp')
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
    current_app.logger.info('URL arguments %s', request.args)
    try:
        req_opts['otp'] = request.args.get('otp')
        if not valid_key_content.match(req_opts['otp']):
            raise ValidationError('Invalid OTP')
            current_app.logger.debug('WOW that was apparently valid')
    except AttributeError:
        current_app.error('Request argument OTP missing')
        raise ValidationError('Required argument OTP missing')
    try:
        req_opts['nonce'] = request.args['nonce']
    except KeyError:
        current_app.error('Request argument nonce missing')
        req_opts['error'] = 'nonce'
        raise ValidationError('required argument nonce missing')
    try:
        req_opts['id'] = request.args['id']
    except KeyError:
        current_app.error('required argument id missing')
        raise ValidationError('required argument id missing')
    if 'timeout' in request.args:
        req_opts['timeout'] = request.args.timeout
    else:
        current_app.logger.info('Request argument timeoute missing')
    if 'sl' in request.args:
        req_opts['sl'] = check_sl(request.args.sl)
        if req_opts['sl'] == 'Error':
            current_app.error('OTP %s Invalid sync level %s' % (req_opts['otp'], req_opts['sl']))
        else:
            current_app.logger.info('Request argument sl missing')
            sl = app.config['__YKVAL_SYNC_DEFAULT_LEVEL__']
    if 'timestamp' in request.args:
        req_opts['timestamp'] = request.args.timestamp
    else:
        current_app.logger.info('Request argument timestamp missing')
    return req_opts


def create_timestamp():
    """
    Create a unix timestamp from the current utc time
    :return unix timestampas in int
    """
    d = datetime.utcnow()
    return timegm(d.utctimetuple())