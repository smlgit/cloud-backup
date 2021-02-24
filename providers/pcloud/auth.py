import urllib.parse as parse
from http.server import HTTPServer
import requests
from common import http_server_utils
from providers.pcloud.server_metadata import PcloudServerData


# Ugggg
# Ports registered on Pcloud
_pcloud_reg_ports = [51283, 58641, 60089]

class GetHandler(http_server_utils.MyHttpServerBaseHandler):

    query_dict = {}

    def do_GET(self):
        GetHandler.query_dict = parse.parse_qs(parse.urlparse(self.path).query)
        self.send_success_response()


def _try_get_free_port():
    for p in _pcloud_reg_ports:
        if http_server_utils.port_in_use(p) == False:
            return p

    raise SystemError('Pcloud authorization couldn\'t find a port for redirect.')


def get_access_token(client_id, user_browser_timeout=600, no_user_form=False):

    port = _try_get_free_port()

    user_form_url = http_server_utils.join_url_components(
        [PcloudServerData.user_form_domain,
         'oauth2/authorize?redirect_uri=http%3A//127.0.0.1%3A{}/xYz'
         '&response_type=code&client_id={}'.format(
              port, client_id)])

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
        raise ValueError('Pcloud auth error: {}'.format(GetHandler.query_dict['error']))

    if 'code' not in GetHandler.query_dict or 'hostname' not in GetHandler.query_dict:
        raise ValueError('Pcloud auth didn\'t return a complete response - {}'.format(
            GetHandler.query_dict))

    # We have an access code, use it to get the final token data
    data = {'code': GetHandler.query_dict['code'],
            'client_id': client_id,
            'client_secret': PcloudServerData.client_secret}

    api_host_domain = 'https://' + GetHandler.query_dict['hostname'][0]

    r = requests.post(
        http_server_utils.join_url_components([api_host_domain, 'oauth2_token']),
        data=data)
    r.raise_for_status()

    # Returned 200
    res = r.json()

    print(res)
    print(r.content)
    if ('access_token' not in res):
        raise ValueError('Malformed access token data received')

    res['api_host_domain'] = api_host_domain

    return res
