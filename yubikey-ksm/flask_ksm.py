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
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/ksm'
app.config['HSM'] = 'yhsm://localhost:5348'
app.config['KEY_HANDLE'] = '1'
app.config['DEBUG'] = True

db = SQLAlchemy(app)

valid_key_content = re.compile('^[cbdefghijklnrtuv]{32,48}$')


class ValidationError(ValueError):
    pass


class Aead(db.Model):
    __tablename__ = 'aead_table'
    public_id = db.Column(db.String(16), primary_key=True)
    keyhandle = db.Column(db.Integer)
    nonce = db.Column(db.BLOB)
    aead = db.Column(db.BLOB)

    def get_url(self):
        return url_for('get_aead', public_id=self.public_id, _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'name': self.name
        }


@app.errorhandler(ValidationError)
def bad_request(e):
    response = jsonify({'status': 400, 'error': 'bad request',
                        'message': e.args[0]})
    response.status_code = 400
    return response


@app.errorhandler(404)
def not_found(e):
    response = jsonify({'status': 404, 'error': 'not found',
                        'message': 'Invalid resource URI : %s' % str(e)})
    response.status_code = 404
    return response


@app.errorhandler(405)
def not_found(e):
    response = jsonify({'status': 405, 'error': 'method not supported',
                        'message': 'the method supplied is not supported'})
    response.status_code = 405
    return response


@app.errorhandler(500)
def internal_server_error(e):
    response = jsonify({'status': 500, 'error': 'internal server error'})
    response.status_code = 500
    return response


@app.route('/wsapi/decrypt')
def get_aead():
    """ Take the otp from url and split the otp into key and public_id
    Do a database look to find the key and return ok or Err
    ccnnccdtrjnevtreclgcdhbbrgkgcknnkkrtuklrugbt
    """

    if not request.args.get('otp'):
        raise ValidationError('otp missing from request')

    else:
        otp = request.args.get('otp')
        public_id, _otp = split_id_otp(otp)
        aead = Aead()
        hsm = YHSM(device=app.config['HSM'], debug=app.config['DEBUG'])
        aead_obj = YHSM_GeneratedAEAD(None, '1', '')
        key_info = aead.query.filter_by(public_id=public_id).first()
        app.logger.warning("DB %s" % key_info.keyhandle)
        if key_info:
            try:
                aead_obj.data = key_info.aead
                aead_obj.nonce = key_info.nonce
                result = validate_yubikey_with_aead(hsm, otp.encode('ascii', 'ignore'), aead_obj, key_info.keyhandle,)
                otp_res = {'result': 'OK',
                           'counter': (result.use_ctr),
                            'low': (result.ts_low),
                            'high': (result.ts_high),
                            'use': (result.session_ctr)
                        }
            except YHSM_Error, e:
                app.logger.warning("IN: %s, Validate FAILED: %s" % (otp, str(e)))
                raise ValidationError('OTP %s, Validate Failed: %s' % (otp, str(e)))

        app.logger.info("OTP - SUCCESS from %s PT hsm %s" % (otp, otp_res))
    return jsonify(otp_res), 200, {'Location': aead.get_url()}


if __name__ == '__main__':
    db.create_all()
    handler = RotatingFileHandler('file.log')
    handler.setLevel(logging.DEBUG)
    app.logger.addHandler(handler)
    app.run(port=5001)