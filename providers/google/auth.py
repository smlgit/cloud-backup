import urllib.parse as parse
from http.server import HTTPServer

import requests

from common import http_server_utils
from providers.google.server_metadata import GoogleServerData


class GetHandler(http_server_utils.MyHttpServerBaseHandler):

    query_dict = {}

    def do_GET(self):
        GetHandler.query_dict = parse.parse_qs(parse.urlparse(self.path).query)
        self.send_success_response()


def get_access_tokens(scope_str, client_id, client_secret,
                      user_browser_timeout=600, no_user_form=False):

    port = http_server_utils.find_free_port()

    user_form_url = GoogleServerData.user_form_domain +\
          '/o/oauth2/v2/auth?scope={}&redirect_uri=http%3A//localhost%3A{}&response_type=code&client_id={}'.format(
              scope_str, port, client_id)

    GetHandler.query_dict = {}
    httpd = HTTPServer(('', port), GetHandler)
    httpd.timeout = user_browser_timeout

    with httpd:
        if no_user_form is False:
            print('In a browser, navigate to the following url and fill out the Google authorization form:')
            print(user_form_url)
        else:
            # If running a local test, we need to act like the user and send the initial request
            r = requests.get(user_form_url)
            r.raise_for_status()

        httpd.handle_request()

    if 'error' in GetHandler.query_dict:
        raise ValueError('Google auth error: {}'.format(GetHandler.query_dict['error']))

    if 'code' not in GetHandler.query_dict:
        raise ValueError('Google auth didn\'t return an access code')

    # We have an access code, use it to get the final token data
    data = {'code': GetHandler.query_dict['code'],
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': 'http://localhost:{}'.format(port),
            'grant_type': 'authorization_code'}

    r = requests.post(GoogleServerData.access_token_domain + '/token', data=data)
    r.raise_for_status()

    # Returned 200
    res = r.json()

    if ('access_token' not in res or 'expires_in' not in res or 'scope' not in res or
                'refresh_token' not in res):
        raise ValueError('Malformed access token data received')

    print(res)
    return res


def refresh_token(client_id, client_secret, ref_token):
    data = {'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': ref_token,
            'grant_type': 'refresh_token'}

    r = requests.post(GoogleServerData.access_token_domain + '/token', data=data)
    r.raise_for_status()

    # Returned 200
    res = r.json()

    if 'access_token' not in res or 'expires_in' not in res or 'scope' not in res:
        raise ValueError('Malformed access token data received')

    return res


def revoke_token(token):
    params = {'token': token}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}

    r = requests.post(GoogleServerData.access_token_domain + '/revoke',
                      params=params, headers=headers)
    r.raise_for_status()


if __name__ == '__main__':
    pass
    # GoogleServerData.set_to_google_server()
    # print(get_access_tokens('https://www.googleapis.com/auth/drive',
    #                        GoogleServerData.client_id,
    #                        GoogleServerData.client_secret))