import json
import common.http_server_utils as http_server_utils


class GoogleTestBaseHandler(http_server_utils.MyHttpServerBaseHandler):

    def testing_handle_google_token_refresh(self):
        """
        If the incoming request is for google token refresh, this function
        will return some dummy credentials so that testing http handlers don't
        have to do it themselves.

        :return: True if the request was a token refresh and was handled.
        """
        if self.path == '/token':
            self.send_success_response(response_content_string=json.dumps(
                {
                    'access_token': 'dummy_access_token',
                    'expires_in': 10000,
                    'scope': 'whatever_scope',
                    'refresh_token': 'dummy_refresh_token'
                }
            ))
            return True

        return False