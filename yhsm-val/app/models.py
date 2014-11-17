from . import db
from flask import url_for


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
        return url_for('api.get_client', _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'id': self.id,
            'active': self.active,
            'created': self.secret,
            'otp': self.otp
            }

    def import_data(self):
        pass


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

    def __init__(self, active, created, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes):
        self.active = active
        self.created = created
        self.yk_publicname = yk_publicname
        self.yk_counter = yk_counter
        self.yk_use = yk_use
        self.yk_low = yk_low
        self.yk_high = yk_high
        self.nonce = nonce
        self.notes = notes

    def __repr__(self):
        return '<Yubikeys %r>' % self.yk_publicname

    def get_url(self):
        return url_for('api.get_yubikey', public_id=self.yk_publicname, _external=True)

    def export_data(self):
        return {
            'self_url': self.get_url(),
            'yk_publicname': self.yk_publicname,
            'yk_counter': self.yk_counter,
            'yk_user': self.yk_use,
            'yk_low': self.yk_low,
            'yk_high': self.yk_high,
            'nonce': self.nonce,
            'active': self.active,
            'created': self.created,
        }

    def import_data(self, data):
        if not all(k in data for k in ('yk_public_name', 'yk_counter', 'yk_user', 'yk_low', 'yk_high', 'nonce', 'active')):
            print "Not all present"
        else:
            return self


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

