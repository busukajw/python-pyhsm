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


@app.route('/wsapi/2.0/verify')
def verify():
    """ """
    if request.method.