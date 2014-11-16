class Sync():
    """process used to check whether an otp is has already been used or is a new otp.
        The first step is to check the local database if the otp is a replayed otp.  Then try and check
        the remote pool of servers
     """
    def __init__(self, sync_servers):
        self._sync_servers = sync_servers

    def sync_servers(self):
        return self._sync_servers

    def get_client_info(self, client_id):
        client = Clients()
        client_info = client.query.filter_by(id=client_id).first()
        return ()
