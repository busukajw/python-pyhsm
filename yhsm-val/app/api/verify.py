import sys
import re
from requests import get, codes
from flask import jsonify, request, current_app
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
sys.path.append('../Lib')
from voluptuous import Schema, Invalid, Required, All, MultipleInvalid
from .sync import Sync
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
        sync = Sync(v_args, current_app.config['__YKVAL_SYNC_POOL__'])
        if 'h' in sync.client_data:
            gen_sig = sync.gen_hmac_sig()
        if sync.otp_params['nonce'] is sync.local_params['nonce'] and \
                sync.local_counters_equal(sync.local_params, sync.otp_params):
            raise ValidationError('Replayed OTP')
        if sync.counters_greater_equal():
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

