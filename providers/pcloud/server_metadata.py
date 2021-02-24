

class PcloudServerData(object):
    """
    Holds fields to specify how to access the drive server.
    One of these class methods MUST be called before accessing
    pcloud services.
    """

    client_id = 'uA2hFrYwpO8'
    client_secret = '1Jv5tsMmr5b99KId0IYHT7BCBA6y'

    @classmethod
    def set_to_pcloud_server(cls):
        cls.user_form_domain = 'https://my.pcloud.com'
        cls.access_token_domain = 'https://api.pcloud.com'

    @classmethod
    def set_to_own_server(cls, domain):
        cls.user_form_domain = domain
        cls.access_token_domain = domain
