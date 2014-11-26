from flask import current_app
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from hashlib import sha1
import hmac
from base64 import b64encode

from ..models import Yubikeys, Clients
from .. import db
from ..exceptions import ValidationError
from ..utils import create_timestamp


class LocalSync():
    def __init__(self):
        pass

    def get_client_id(self, client_id):
        """
        Fetch the client ID
        :param client_id:
        :return: the client id
        """
        try:
            client = Clients.query.filter_by(id=client_id).one()
        except MultipleResultsFound:
            raise ValidationError('More than one Client found matching ID %s' % client_id)
        except NoResultFound:
            raise ValidationError('Client ID %s does not exist' % client_id)
        return client.id

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


    def get_local_sync_record(self,public_id, otp):
        """
        lookup the latest sync settings for any given public_id and return a hash of those settings
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

    def local_nonce_check(self, lsync_nonce, lsync_otp, rsync_nonce, rsync_otp):
        """
        compare locally stored nonce and otp with clients nonce and otp is they are identical the the check fails
        :param lsync_nonce:
        :param lsync_otp
        :param rsync_nonce:
        :param rsync_otp:
        :return True if all is ok and False if info is identical:
        """
        if lsync_otp == rsync_otp and lsync_nonce == rsync_nonce:
            r = False
        else:
            current_app.logger.debug('local_replay_check passed')
            r = True
        return r

    def local_counter_check(self, lsync_info, otp_sync_info):
        """
         Check the local counters against the the otp generated counters and return false if the local counters are
         greater than or equal than the otp generated counters
        :param lsync_info: dict containing the locally stored counters
        :param otp_sync_info: dict containgin the otp generated counters
        :return: False if test fails and true if the test passes
        """
        if lsync_info['counter'] >= otp_sync_info['counter'] or lsync_info['use'] >= otp_sync_info['use']:
            r = False
        else:
            r = True
        return r

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

    def gen_hmac_sig(self, http_opts, api_key):
        """Generate a signature based on the returned http get options whilst  removing the h option if it is present.
        The dictionary is then sorted alphabetically on the key use HMAC SHA1 to create the signature
        args: key_pairs : a dictionary of key paris
        returns: a bas64encoded string
        """
        sorted_list = [key + '=' + ''.join(http_opts[key]) for key in sorted(http_opts.keys()) if key != 'h)']
        sig = hmac.new(api_key, '&'.join(sorted_list), sha1)
        return b64encode(sig.digest())