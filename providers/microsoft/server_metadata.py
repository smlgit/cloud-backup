

class MicrosoftServerData(object):
    """
    Holds fields to specify how to access the drive server.
    One of these class methods MUST be called before accessing
    microsoft services.
    """

    client_id = '3e960ac7-2341-4293-ad08-a4892e191fcf'

    @classmethod
    def set_to_microsoft_server(cls):
        cls.user_form_domain = 'https://login.microsoftonline.com'
        cls.access_token_domain = 'https://login.microsoftonline.com'
        cls.apis_domain = 'https://graph.microsoft.com'

    @classmethod
    def set_to_own_server(cls, domain):
        cls.user_form_domain = domain
        cls.access_token_domain = domain
        cls.apis_domain = domain
