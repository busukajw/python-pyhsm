import sys
import re
from requests import get, codes
from flask import jsonify, request, current_app
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
sys.path.append('../Lib')
from pyhsm.yubikey import split_id_otp
from voluptuous import Schema, Invalid, Required, All, MultipleInvalid
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
        v_args = check_parms(request)
        sync = LocalSync(v_args)
        if 'h' in sync.client_data:
            gen_sig = sync.gen_hmac_sig()
        # call remote ksm and check for valid otp
        otp_result = lookup_otp(sync.client_data['otp'], '127.0.0.1:5001')
        if not otp_result['result'] == 'OK':
            raise ValidationError('OTP lookup ERROR %s' % (otp_result['message']))
        else:
            public_id, otp = split_id_otp(sync.client_data['otp'])
            otp_params = {'public_id': public_id,
                          'otp': otp,
                          'nonce': sync.client_data['nonce']}
            otp_params.update(otp_result)
            local_params = sync.get_local_sync_record(public_id, otp)
            current_app.logger.debug('local sync info %s' % local_params)
            # check to see if client nonce and client otp session use and counter are identical in local DB
            if otp_params['nonce'] is local_params['nonce'] and sync.local_counter_equal(local_params, otp_params):
                raise ValidationError('Replayed OTP')
            if sync.counters_greater_equal(local_params,otp_params):
                raise ValidationError('Replayed OTP')
            else:
                sync.insert_lsyncdb(otp_params)
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
    Check the parameters to make sure that all parameters are correct and return a dictionary with the keys that
    the application knows about
    :param request: request obj
    :return: a dictionary of the uri parameter key value pairs
    """
    current_app.logger.info('in check parms')
    valid_params = ['otp', 'id', 'h', 'nonce', 'timeout', 'timestamp', 'sl']
    data = {key: value for (key, value) in request.args.iteritems() if key in valid_params}
    current_app.logger.info(data)
    schema = Schema({
        Required('otp'): All(otp_valid_chars()),
        Required('nonce'): All(unicode),
        Required('id'): All(valid_client_id()),
        'timeout': All(int),
        'h': All(str),
        'timestamp': All(str),
        'sl': All(str),
    })
    try:
        schema(data)
    except MultipleInvalid as e:
        raise ValidationError(str(e))

    return data

