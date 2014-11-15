import os


basedir = os.path.abspath(os.path.dirname(__file__))
DEBUG = True

LOG_FILE='var.log'

SQLALCHEMY_DATABASE_URI = 'mysql://root:@localhost:3306/val'
HSM = 'yhsm://localhost:5348'
KEY_HANDLE = '1'

# Specify how often the sync daemon awakens
__YKVAL_SYNC_INTERVAL__ = 10;
# Specify how long the sync daemon will wait for response
__YKVAL_SYNC_RESYNC_TIMEOUT__ = 30;
# Specify how old entries in the database should be considered aborted attempts
__YKVAL_SYNC_OLD_LIMIT__ = 10;

# These are settings for the validation server.
__YKVAL_SYNC_FAST_LEVEL__ = 1;
__YKVAL_SYNC_SECURE_LEVEL__ = 40;
__YKVAL_SYNC_DEFAULT_LEVEL__ = 60;
__YKVAL_SYNC_DEFAULT_TIMEOUT__ = 1;
__YKVAL_SYNC_POOL__ = ['localhost', '192.192.1.1']

