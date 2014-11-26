import sys
import re
from requests import get, codes
from base64 import b64decode
from flask import jsonify, request, current_app
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
sys.path.append('../Lib')
from pyhsm.yubikey import split_id_otp
from voluptuous import Schema, Invalid, Required, All
from .sync import LocalSync
from . import api
from .. import db
from ..exceptions import ValidationError
from ..models import Clients, Yubikeys



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
        sync = LocalSync()
        otp_result = {}
        current_app.logger.info(request.url)
        # check for required request arguments
        v_args = check_parms(request)
        if 'error' not in v_args:
            client_id = sync.get_client_id(v_args['id'])
            if 'h' in v_args:
                if not sync.verify_sig(v_args['h'], sync.gen_hmac_sig(request.args, get_api_key(client_id))):
                    raise ValidationError('S_BAD_SIGNATURE')
            # call remote ksm and check for valid otp
            otp_result = lookup_otp(v_args['otp'], '127.0.0.1:5001')
            if not otp_result['result'] == 'OK':
                raise ValidationError('OTP lookup ERROR %s' % (otp_result['message']))
            else:
                public_id, otp = split_id_otp(v_args['otp'])
                local_sync_info = sync.get_local_sync_record(public_id, otp)
                otp_sync_info = otp_result
                otp_sync_info['nonce'] = v_args['nonce']
                otp_sync_info['public_id'] = public_id
                otp_sync_info['otp'] = otp
                current_app.logger.debug('local sync info %s' % local_sync_info)
                if not sync.local_nonce_check(local_sync_info['nonce'], local_sync_info['otp'],
                                         otp_sync_info['nonce'], otp_sync_info['otp']):
                    raise ValidationError('Replayed OTP')
                if not sync.local_counter_check(local_sync_info, otp_sync_info):
                    raise ValidationError('Local Counters higher than OTP Counters: Replayed OTP')
                sync.insert_lsyncdb(otp_sync_info)
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



def make_request(url, host, payload=None, http_type='GET', timeout=2):
    """
    Create and make a single request and return the request as a dict
    :param url: the url
    :param host: host name
    :param payload: payload as a dict
    :param http_type: http message type PUT, GET etc...
    :param timeout: timeout in seconds to wait for initial response
    :return: a json obj
    """
    comp_url = host + url
    current_app.logger.debug('created url = %s' % comp_url)
    if http_type == 'GET':
        r = get(comp_url, params=payload, timeout=timeout)
    if r.status_code != codes.ok:
        current_app.logger.debug('Error making http connection %s ')
        result = {}
    else:
        result = r.json()
    return result

def lookup_otp(otp, keyserver):
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
    return r.json()


def check_nonce(nonce):
    """
    Make sure that the nonce (random string) has not been used before to make sure that
    :param nonce:
    :return true or false:
    """
    pass


def otp_valid_chars(msg=None):
    """
    Check that the characters are valid possible chars and that the length of the otp is correct
    :param otp: the supplied otp
    :return: True if the otp pass's test
    """
    def f(v):
        valid_key_content = re.compile('^[cbdefghijklnrtuv]{32,48}$')
        if valid_key_content.match(v):
            return str(v)
        else:
            raise Invalid(msg or ("Incorrect OTP"))
    return f


def valid_client_id(msg=None):
    def f(v):
        try:
            Clients.query.filter_by(id=v).one()
        except MultipleResultsFound:
            raise Invalid('Multiple Client ID returned')
        except NoResultFound:
            raise Invalid('No Client ID returned')
    return f


def check_parms(request):
    """
    Check the parameters to make sure that all parameters are correct
    :param params:
    :return:
    """

    schema = Schema({
        Required('otp'): All(otp_valid_chars()),
        Required('nonce'): All(str),
        Required('id'): All(valid_client_id()),
        'timeout': All(int),
        'h': All(str),
        'timestamp': All(str),
        'sl': All(str),
    })

    return req_opts

