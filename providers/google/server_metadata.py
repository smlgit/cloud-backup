

class GoogleServerData(object):
    """
    Holds fields to specify how to access the drive server.
    One of these class methods MUST be called before accessing
    google services.
    """

    client_id = '145413420291-beb08njh611mkf8m24el5asbhhbijg52.apps.googleusercontent.com'
    client_secret = 'WX7VZ-jFNxLPAlME5UDPpIVP'

    @classmethod
    def set_to_google_server(cls):
        cls.user_form_domain = 'https://accounts.google.com'
        cls.access_token_domain = 'https://oauth2.googleapis.com'
        cls.apis_domain = 'https://www.googleapis.com'

    @classmethod
    def set_to_own_server(cls, domain):
        cls.user_form_domain = domain
        cls.access_token_domain = domain
        cls.apis_domain = domain
