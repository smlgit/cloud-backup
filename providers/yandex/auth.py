import urllib.parse as parse
from http.server import HTTPServer
import requests
from common import http_server_utils
from providers.yandex.server_metadata import YandexServerData


class GetHandler(http_server_utils.MyHttpServerBaseHandler):

    query_dict = {}

    def do_GET(self):
        GetHandler.query_dict = parse.parse_qs(parse.urlparse(self.path).query)
        self.send_success_response()


def get_access_tokens(client_id, client_secret,
                      user_browser_timeout=600, no_user_form=False):

    port = http_server_utils.try_get_free_port()

    user_form_url = http_server_utils.join_url_components(
        [YandexServerData.oauth_domain,
         'authorize?redirect_uri=http%3A//127.0.0.1%3A{}/myapp'
         '&response_type=code&client_id={}'.format(
              port, client_id)])

    GetHandler.query_dict = {}
    httpd = HTTPServer(('', port), GetHandler)
    httpd.timeout = user_browser_timeout

    with httpd:
        if no_user_form is False:
            print('In a browser, navigate to the following url and fill out the Yandex authorization form:')
            print(user_form_url)
        else:
            # If running a local test, we need to act like the user and send the initial request
            r = requests.get(user_form_url)
            r.raise_for_status()

        httpd.handle_request()

    if 'error' in GetHandler.query_dict:
        raise ValueError('Yandex auth error: {}, {}'.format(
            GetHandler.query_dict['error'],
            GetHandler.query_dict['error_description']))

    if 'code' not in GetHandler.query_dict:
        raise ValueError('Yandex auth didn\'t return an access code - {}'.format(
            GetHandler.query_dict
        ))

    # We have an access code, use it to get the final token data
    data = {'code': GetHandler.query_dict['code'],
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'authorization_code'}

    r = requests.post(
        http_server_utils.join_url_components(
            [YandexServerData.oauth_domain, '/token']),
        data=data)
    print(r.content)
    r.raise_for_status()

    # Returned 200
    res = r.json()

    if ('access_token' not in res or 'expires_in' not in res or
                'refresh_token' not in res):
        raise ValueError('Malformed access token data received: {}'.format(res))

    return res


def refresh_token(client_id, client_secret, ref_token):
    data = {'refresh_token': ref_token,
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'refresh_token'}

    r = requests.post(
        http_server_utils.join_url_components(
            [YandexServerData.oauth_domain, '/token']),
        data=data)
    r.raise_for_status()

    # Returned 200
    res = r.json()

    if ('access_token' not in res or 'expires_in' not in res or
                'refresh_token' not in res):
        raise ValueError('Malformed access token data received: {}'.format(res))

    return res
