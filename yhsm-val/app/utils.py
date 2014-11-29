from datetime import datetime
from calendar import timegm
from numpy.random.mtrand import RandomState
from binascii import b2a_hex


def create_timestamp():
    """
    Create a unix timestamp from the current utc time
    :return unix timestampas in int
    """
    d = datetime.utcnow()
    return timegm(d.utctimetuple())


def server_nonce():
    """
    Create a random string
    :return:  a random string
    """
    rand = RandomState()
    lo=1000000000000000
    hi=999999999999999999
    return b2a_hex(rand.randint(lo, hi, 3).tostring())[:32]