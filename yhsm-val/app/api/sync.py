from flask import current_app
from sqlalchemy.orm.exc import NoResultFound
from hashlib import sha1
import hmac
from requests import get
from base64 import b64encode, b64decode
from pyhsm.yubikey import split_id_otp
from ..models import Yubikeys, Clients
from .. import db
from ..exceptions import ValidationError
from ..utils import create_timestamp


class Sync():
    def __init__(self, client_data, sync_servers):
        self.client_data = client_data
        otp_params = self._generate_otp_params()
        self.otp_params = otp_params
        local_params = self._get_local_sync_record()
        self.local_params = local_params
        self.sync_servers = sync_servers

    def local_params(self):
        return self.local_params

    def otp_params(self):
        return self.otp_params

    def client_data(self):
        return self.client_data

    def sync_servers(self):
        return self.sync_servers

    def insert_lsyncdb(self, sync_info):
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

    def _get_local_sync_record(self):
        """
        lookup the latest sync settings for any given public_id and return a hash of those settings
        :rtype : object
        :param public_id:
        :param otp:
        :return: a hash public_id: public_id
                        counter: session_counter
                        use: session_use
                        high: high
                        low: low
                        nonce: nonce
                        otp: otp

        """
        public_id = self.otp_params['public_id']
        otp = self.otp_params['otp']
        try:
            yubikey = Yubikeys.query.filter_by(yk_publicname=public_id).one()
            current_app.logger.debug('ID found %s' % yubikey)
        except NoResultFound:
            current_app.logger.debug('The Id does not exist in DB')
            yubikey = Yubikeys(active=1, yk_publicname=public_id, yk_counter=-1, yk_high=-1, yk_low=-1, yk_use=-1)
            db.session.add(yubikey)
            db.session.commit()
            self.get_local_sync_record(public_id, otp)

        return {'public_id': public_id,
                'counter': yubikey.yk_counter,
                'use': yubikey.yk_use,
                'high': yubikey.yk_high,
                'low': yubikey.yk_low,
                'nonce': yubikey.nonce,
                'otp': otp}

    def local_counters_equal(self):
        """
        Check to see is the session counter and use counter stored in db are the same as the ones provided in the
         otp.
        :return: return true if counters are identical
        """
        lsync_info = self.local_params
        otp_sync_info = self.otp_params
        if lsync_info['counter'] is otp_sync_info['counter'] and lsync_info['use'] is otp_sync_info['use']:
            return True

    def counters_greater_equal(self):
        """
         Check the local counters against the the otp generated counters and return false if the local counters are
         greater than or equal than the otp generated counters
        :return: False if test fails and true if the test passes
        """
        lsync_info = self.local_params
        otp_sync_info = self.otp_params
        if lsync_info['counter'] >= otp_sync_info['counter'] or lsync_info['use'] >= otp_sync_info['use']:
            return True

    def verify_sig(self, orig_sig, gen_sig):
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

    def gen_hmac_sig(self):
        """Generate a signature based on the returned http get options whilst  removing the h option if it is present.
        The dictionary is then sorted alphabetically on the key use HMAC SHA1 to create the signature
        returns: a bas64encoded string
        """
        api_key = self._get_api_key()
        sorted_list = [key + '=' + ''.join(self.client_data) for key in sorted(self.client_data.keys()) if key != 'h)']
        sig = hmac.new(api_key, '&'.join(sorted_list), sha1)
        return b64encode(sig.digest())

    def _get_api_key(self):
        """Given a client id lookup the ID and return the api key and base64 decode it
        args: id:  client id
        returns the raw api key"""
        api_key = Clients.query.filter_by(id=self.client_data['id']).one()
        return b64decode(api_key)

    def add_queue(self):
        local_params = self.client_data
        time = create_timestamp()

    def _generate_otp_params(self):
        """
        using the otp in the client_data generate all of the otp_params needed
        'public_id', 'otp', 'nonce',counters, 'use', 'high', 'low'
        :return: a dict which has all of the otp_params
        """
        public_id, _ = split_id_otp(self.client_data['otp'])
        otp_result = self._lookup_otp()
        otp_params = {'public_id': public_id,
                      'nonce': self.client_data['nonce'],
                      'otp': self.client_data['otp']}
        return otp_params.udpate(otp_result)

    def _lookup_otp(self):
        """
        given an otp send a request to the keyserver asking if the otp is valid
        args:
            otp: the otp :-)
            keyserver: the ip address of the keyserver to use to check the otp
        :return:
        """
        payload = {'otp': self.client_data['otp']}
        current_app.logger.info('in lookup_otp')
        url = 'http://localhost:5001/wsapi/decrypt'
        r = get(url, params=payload)
        return r.json()
