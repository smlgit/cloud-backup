

class YandexServerData(object):
    """
    Holds fields to specify how to access the drive server.
    One of these class methods MUST be called before accessing
    yandex services.
    """

    client_id = '2a8b43894a744cef8b1c9e3dedbade38'
    client_secret = 'b8121d4fc6c343e98852dde056f3abbd'

    @classmethod
    def set_to_yandex_server(cls):
        cls.oauth_domain = 'https://oauth.yandex.com'
        cls.apis_domain = 'https://cloud-api.yandex.net'

    @classmethod
    def set_to_own_server(cls, domain):
        cls.oauth_domain = domain
        cls.apis_domain = domain
