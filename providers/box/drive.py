import datetime
import logging
import os
import time

import requests
from dateutil import parser as date_parser

import providers.box.auth as auth
from common import http_server_utils
import common.config_utils as config_utils
from common.tree_utils import StoreTree
import common.hash_utils as hash_utils
from providers.box.server_metadata import BoxServerData


logger = logging.getLogger(__name__)


def _get_config_file_name(account_name):
    return account_name + '-box-cbconfig.data'


def _get_config_file_full_path(config_dir_path, account_name):
    return os.path.join(config_dir_path, _get_config_file_name(account_name))


class BoxDrive(object):
    def __init__(self, account_id, config_dir_path, config_pw):
        self._config = {'account_name': account_id}
        self._config_dir_path = config_dir_path
        self._config_pw = config_pw
        self._api_drive_endpoint_prefix = http_server_utils.join_url_components(
            [BoxServerData.apis_domain, '2.0'])
        self._load_config(account_id)

    def _save_config(self):
        config_utils.save_config(self._config,
                                 _get_config_file_full_path(self._config_dir_path,
                                                            self._config['account_name']),
                                 self._config_pw)

    def _load_config(self, account_name):
        if account_name == 'local_test_acc':
            # False credentials for local server testing
            self._config = {
                "account_name": account_name,
                "auth": {
                    "access_token": "local_test_access_token",
                    "token_type": "Bearer"}
            }
        else:
            try:
                self._config = config_utils.get_config(
                    _get_config_file_full_path(self._config_dir_path,
                                               self._config['account_name']),
                    self._config_pw
                )
            except:
                logger.warning('Failed to open Box config file for account {}, '
                               'user will need to authenticate before accessing the drive.'.format(
                    account_name
                ))
                self._config = {'account_name': account_name}


    def _get_auth_header(self):
        """"""
        return 'Bearer ' + self._config['auth']['access_token']


    def _refresh_token_required(self):
        # refresh if we only have 5 minutes left
        return (self._config['auth']['expires_at'] <
                datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=5))


    def _do_request(self, method, url, headers={}, params={}, data={}, json=None,
                    files={}, server_error_retries=10, raise_for_status=True):
        """
        Does a standard requests call with the passed params but also:
            1. Sets the authorization header
            2. Will check for server errors in the response and back off if
               needed or raise an exception if appropriate.

        :param method: one of 'get', 'post', 'put', 'delete'
        :param server_error_retries: set to the number of retries when encountering
        a pesky Server Error.
        :return: (r, rx_dict) tuple
        """


        if method == 'get':
            func = requests.get
        elif method == 'post':
            func = requests.post
        elif method == 'put':
            func = requests.put
        elif method == 'patch':
            func = requests.patch
        elif method == 'delete':
            func = requests.delete

        if self._refresh_token_required():
            self.refresh_token()

        rx_dict = {}

        retries = 0
        current_sleep_time = 1

        while True:

            headers['Authorization'] = self._get_auth_header()
            r = func(url, headers=headers, params=params, data=data, json=json, files=files)

            # Success
            if (r.status_code > 199 and r.status_code < 300 and
                        'application/json' in r.headers['Content-Type']):
                # Check to see if there are errors in the response
                try:
                    rx_dict = r.json()
                except:
                    pass

                break
            elif r.status_code == 429:
                # Too many requests
                if 'retry-after' in r.headers:
                    current_sleep_time = r.headers['retry-after']
                else:
                    current_sleep_time *= 2

                if retries > server_error_retries:
                    raise SystemError('Too many retries to Box')

                retries += 1

        if raise_for_status == True:
            r.raise_for_status()

        return r, rx_dict


    @staticmethod
    def required_config_is_present(config_dir_path, account_name):
        return os.path.exists(_get_config_file_full_path(config_dir_path, account_name))


    def run_token_acquisition(self):
        self._config['auth'] = auth.get_access_tokens(BoxServerData.client_id,
                                                      BoxServerData.client_secret)
        self._config['auth']['expires_at'] = \
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(self._config['auth']['expires_in']))
        self._save_config()


    def refresh_token(self):
        self._config['auth'] = auth.refresh_token(BoxServerData.client_id,
                                                  BoxServerData.client_secret,
                                                  self._config['auth']['refresh_token'])
        self._config['auth']['expires_at'] = \
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(self._config['auth']['expires_in']))
        self._save_config()


    def revoke_token(self):
        auth.revoke_token(BoxServerData.client_id,
                          BoxServerData.client_secret,
                          self._config['auth']['access_token'])
        self._config['auth'] = {}
        self._save_config()


if __name__ == '__main__':
    BoxServerData.set_to_box_server()
    d = BoxDrive('smlgit', os.getcwd(), '')
    d.refresh_token()
