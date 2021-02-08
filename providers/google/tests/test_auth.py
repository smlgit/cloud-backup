import json
import time
import unittest
from http.server import HTTPServer
from threading import Thread
from urllib import parse

import requests

from common import http_server_utils
from providers.google.auth import get_access_tokens, refresh_token, revoke_token
from providers.google.server_metadata import GoogleServerData


def _cloud_server_thread(cloud_server_instance):
    cloud_server_instance.serve_forever()


class GetAccessTokenHandler(http_server_utils.MyHttpServerBaseHandler):

    # =================================================================
    # Some class fields that the test cases can modify to set expected
    # requests and response data. Also some fields to specify if an error
    # is send back at various points in the exchange.

    # Requests/reponses
    inital_request_expected = {}
    access_token_request_expected = {}
    access_token_response = {}

    # errors
    auth_error = False
    error_400_on_initial_request = False
    error_400_on_token_request = False


    def do_GET(self):

        # Expecting initial auth request
        url_data = parse.urlparse(self.path)
        url_query_vars = http_server_utils.query_string_to_dict_without_lists(parse.urlparse(self.path).query)

        if url_data.path != '/o/oauth2/v2/auth':
            self.send_error(400, message='Requested url is malformed')
            return

        if GetAccessTokenHandler.error_400_on_initial_request is True:
            self.send_error(400, message='400 error for test...')
            return

        # Can't check client port number, so just check expected values in request are correct
        for k, v in GetAccessTokenHandler.inital_request_expected.items():
            if (k not in url_query_vars or
                        GetAccessTokenHandler.inital_request_expected[k] != url_query_vars[k]):
                self.send_error(400, message='Requested url is malformed, missing or wrong val for key {}'.format(k))
                return

        # Seems good, send good response, then send the access code to the redirect url
        self.send_success_response()

        time.sleep(1)

        params = {}
        if GetAccessTokenHandler.auth_error is True:
            params['error'] = 'access_denied'
        elif 'code' in GetAccessTokenHandler.access_token_request_expected:
            params['code'] = GetAccessTokenHandler.access_token_request_expected['code']

        requests.get(
            url_query_vars['redirect_uri'].replace('https', 'http'), params=params)

    def do_POST(self):

        # check for correct url
        url_data = parse.urlparse(self.path)
        url_query_vars = http_server_utils.query_string_to_dict_without_lists(parse.urlparse(self.path).query)

        if url_data.path != '/token':
            self.send_error(400, message='Requested url is malformed')
            return

        # check correct content type
        if self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            self.send_error(400, message='Incorrect content type in POST request')
            return

        if GetAccessTokenHandler.error_400_on_token_request is True:
            self.send_error(400, message='400 error for test...')
            return

        # Check the valid params were received
        rx_params = http_server_utils.query_string_to_dict_without_lists(
            self.rfile.read(int(self.headers['Content-Length'])).decode())

        # Can't check client port number (so can't check redirect_url), so just check expected
        # values in request are correct
        for k, v in GetAccessTokenHandler.access_token_request_expected.items():
            if (k not in rx_params or
                        GetAccessTokenHandler.access_token_request_expected[k] != rx_params[k]):
                self.send_error(400, message='Token request is malformed: {}'.format(rx_params))
                return

        self.send_success_response(response_content_string=json.dumps(GetAccessTokenHandler.access_token_response))


class RevokeTokenHandler(http_server_utils.MyHttpServerBaseHandler):

    # =================================================================
    # Some class fields that the test cases can modify to set expected
    # requests and response data. Also some fields to specify if an error
    # is send back at various points in the exchange.

    # Requests/reponses
    expected_token = ''

    # errors
    error_400_on_initial_request = False


    def do_POST(self):

        # check for correct url
        url_data = parse.urlparse(self.path)
        url_query_vars = http_server_utils.query_string_to_dict_without_lists(parse.urlparse(self.path).query)

        if url_data.path != '/revoke':
            self.send_error(400, message='Requested url is malformed')
            return

        # check correct content type
        if self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            self.send_error(400, message='Incorrect content type in POST request')
            return

        if RevokeTokenHandler.error_400_on_initial_request is True:
            self.send_error(400, message='400 error for test...')
            return


        if 'token' not in url_query_vars:
            self.send_error(400, message='token parameter missing from query string')
            return

        if url_query_vars['token'] != RevokeTokenHandler.expected_token:
            self.send_error(400, message='token parameter {} doesn\'t match expected {}'.format(
                url_query_vars['token'],
                RevokeTokenHandler.expected_token
            ))
            return

        # Successful revocation
        self.send_success_response()


class TestAuth(unittest.TestCase):

    def _start_cloud_server(self, Handler):
        self.cloud_server = HTTPServer(('', http_server_utils.find_free_port()), Handler)
        GoogleServerData.set_to_own_server('http://127.0.0.1:{}'.format(self.cloud_server.server_port))

        Thread(target=_cloud_server_thread, args=(self.cloud_server,), daemon=True).start()

    def setUp(self):
        self.cloud_server = None

        GetAccessTokenHandler.error_400_on_initial_request = False
        GetAccessTokenHandler.error_400_on_token_request = False
        GetAccessTokenHandler.auth_error = False

        RevokeTokenHandler.error_400_on_initial_request = False

    def tearDown(self):
        if self.cloud_server is not None:
            self.cloud_server.server_close()

    def testGetAccessTokenNoError(self):
        self._start_cloud_server(GetAccessTokenHandler)

        GetAccessTokenHandler.inital_request_expected = {
            'scope' : 'drive/files drive/ted',
            'client_id' : '123987',
        }
        GetAccessTokenHandler.access_token_request_expected = {
            'code': 'HHENNnkfoNOEnon__983mfe(#',
            'client_id': GetAccessTokenHandler.inital_request_expected['client_id'],
            'client_secret': 'JeomOEpmefpmepmf##',
            'grant_type': 'authorization_code'
        }

        GetAccessTokenHandler.access_token_response = {
            'access_token': 'skFKLSljFSjos89893__23r23-',
            'expires_in': 100,
            'scope': GetAccessTokenHandler.inital_request_expected['scope'],
            'refresh_token': 'Jmkno999',
            'token_type': 'Bearer'
        }

        access_token_data = get_access_tokens(GetAccessTokenHandler.access_token_response['scope'],
                                              GetAccessTokenHandler.access_token_request_expected['client_id'],
                                              GetAccessTokenHandler.access_token_request_expected['client_secret'],
                                              user_browser_timeout=5,
                                              no_user_form=True)

        self.assertEqual(access_token_data, GetAccessTokenHandler.access_token_response)

    def testGetAccessAuthError(self):
        GetAccessTokenHandler.inital_request_expected = {
            'scope': 'drive/files drive/ted',
            'client_id': '123987',
        }
        GetAccessTokenHandler.auth_error = True

        self._start_cloud_server(GetAccessTokenHandler)

        with self.assertRaises(ValueError):
            get_access_tokens(GetAccessTokenHandler.inital_request_expected['scope'],
                              GetAccessTokenHandler.inital_request_expected['client_id'],
                              '',
                              user_browser_timeout=5,
                              no_user_form=True)

    def testGetAccess400ErrorOnInitial(self):
        GetAccessTokenHandler.inital_request_expected = {
            'scope': 'drive/files drive/ted',
            'client_id': '123987',
        }
        GetAccessTokenHandler.error_400_on_initial_request = True

        self._start_cloud_server(GetAccessTokenHandler)

        with self.assertRaises(requests.exceptions.HTTPError):
            get_access_tokens(GetAccessTokenHandler.inital_request_expected['scope'],
                              GetAccessTokenHandler.inital_request_expected['client_id'],
                              '',
                              user_browser_timeout=5,
                              no_user_form=True)

    def testGetAccess400ErrorOnTokenRequest(self):
        self._start_cloud_server(GetAccessTokenHandler)

        GetAccessTokenHandler.inital_request_expected = {
            'scope': 'drive/files drive/ted',
            'client_id': '123987',
        }
        GetAccessTokenHandler.access_token_request_expected = {
            'code': 'HHENNnkfoNOEnon__983mfe(#',
            'client_id': GetAccessTokenHandler.inital_request_expected['client_id'],
            'client_secret': 'JeomOEpmefpmepmf##',
            'grant_type': 'authorization_code'
        }

        GetAccessTokenHandler.error_400_on_token_request = True

        with self.assertRaises(requests.exceptions.HTTPError):
            get_access_tokens(GetAccessTokenHandler.inital_request_expected['scope'],
                              GetAccessTokenHandler.inital_request_expected['client_id'],
                              GetAccessTokenHandler.access_token_request_expected['client_secret'],
                              user_browser_timeout=5,
                              no_user_form=True)

    def testRefreshToken(self):
        GetAccessTokenHandler.access_token_request_expected = {
            'client_id': '34532',
            'client_secret': 'JeomOEpmefpmepmf##',
            'refresh_token': 'mnsoOFofnof___7',
            'grant_type': 'refresh_token'
        }
        GetAccessTokenHandler.access_token_response = {
            "access_token": 'skFKLSljFSjos89893__23r23-',
            'expires_in': 1000,
            'scope': 'rando_scope/scope drive/scope',
            'token_type': 'Bearer'
        }

        self._start_cloud_server(GetAccessTokenHandler)

        access_token_data = refresh_token(GetAccessTokenHandler.access_token_request_expected['client_id'],
                                          GetAccessTokenHandler.access_token_request_expected['client_secret'],
                                          GetAccessTokenHandler.access_token_request_expected['refresh_token'])
        self.assertEqual(access_token_data, GetAccessTokenHandler.access_token_response)

    def testRefreshToken400Error(self):
        GetAccessTokenHandler.access_token_request_expected = {
            'client_id': '34532',
            'client_secret': 'JeomOEpmefpmepmf##',
            'refresh_token': 'mnsoOFofnof___7',
            'grant_type': 'refresh_token'
        }
        GetAccessTokenHandler.error_400_on_token_request = True

        self._start_cloud_server(GetAccessTokenHandler)

        with self.assertRaises(requests.exceptions.HTTPError):
            refresh_token(GetAccessTokenHandler.access_token_request_expected['client_id'],
                          GetAccessTokenHandler.access_token_request_expected['client_secret'],
                          GetAccessTokenHandler.access_token_request_expected['refresh_token'])

    def testRevokeTokenNoError(self):
        RevokeTokenHandler.expected_token = 'JFEOSEOosJfekn-i-2_(JJ'

        self._start_cloud_server(RevokeTokenHandler)

        revoke_token(RevokeTokenHandler.expected_token)

    def testRevokeTokenInvalidToken(self):
        RevokeTokenHandler.expected_token = 'JFEOSEOosJfekn-i-2_(JJ'

        self._start_cloud_server(RevokeTokenHandler)

        with self.assertRaises(requests.exceptions.HTTPError):
            revoke_token(RevokeTokenHandler.expected_token + 'a')

    def testRevokeToken400ErrorOnRequest(self):
        RevokeTokenHandler.expected_token = 'JFEOSEOosJfekn-i-2_(JJ'
        RevokeTokenHandler.error_400_on_initial_request = True

        self._start_cloud_server(RevokeTokenHandler)

        with self.assertRaises(requests.exceptions.HTTPError):
            revoke_token(RevokeTokenHandler.expected_token)

