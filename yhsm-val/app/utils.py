from datetime import datetime
from calendar import timegm

def create_timestamp():
    """
    Create a unix timestamp from the current utc time
    :return unix timestampas in int
    """
    d = datetime.utcnow()
    return timegm(d.utctimetuple())
