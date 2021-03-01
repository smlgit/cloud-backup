

class BoxServerData(object):
    """
    Holds fields to specify how to access the drive server.
    One of these class methods MUST be called before accessing
    Box services.
    """

    client_id = 'e4c7h5e1hd6f73buturzgcsfjh1xv47v'
    client_secret = 'VTmZYDZ8yTd2FRHLqc2aIc6xtS4Qd66l'

    @classmethod
    def set_to_box_server(cls):
        cls.user_form_domain = 'https://account.box.com'
        cls.access_token_domain = 'https://api.box.com'
        cls.apis_domain = 'https://api.box.com'

    @classmethod
    def set_to_own_server(cls, domain):
        cls.user_form_domain = domain
        cls.access_token_domain = domain
        cls.apis_domain = domain
