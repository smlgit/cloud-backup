import datetime
import logging
import os
import time

import requests
from dateutil import parser as date_parser

import providers.yandex.auth as auth
from common import http_server_utils
import common.config_utils as config_utils
from common.tree_utils import StoreTree
import common.hash_utils as hash_utils
from providers.yandex.server_metadata import YandexServerData


logger = logging.getLogger(__name__)



def _get_config_file_name(account_name):
    return account_name + '-yandex-cbconfig.data'


def _get_config_file_full_path(config_dir_path, account_name):
    return os.path.join(config_dir_path, _get_config_file_name(account_name))


def _convert_yandex_to_standard_path(yandex_path):
    return StoreTree.standardise_path(yandex_path.replace(':disk', ''))


def _convert_standard_to_yandex_path(standard_path):
    return '/' + standard_path


class YandexDrive(object):
    def __init__(self, account_id, config_dir_path, config_pw):
        self._config = {'account_name': account_id}
        self._config_dir_path = config_dir_path
        self._config_pw = config_pw
        self._api_drive_endpoint_prefix = http_server_utils.join_url_components(
            [YandexServerData.apis_domain, 'v1/disk'])
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
                logger.warning('Failed to open Yandex config file for account {}, '
                               'user will need to authenticate before accessing the drive.'.format(
                    account_name
                ))
                self._config = {'account_name': account_name}

    def _get_auth_header(self):
        """"""
        return 'OAuth ' + self._config['auth']['access_token']


    def _do_request(self, method, url, headers={}, params={}, data={}, json=None,
                    files={}, raise_for_status=True):
        """
        Does a standard requests call with the passed params but also:
            1. Sets the authorization header
            2. Will check for server errors in the response and back off if
               needed or raise an exception if appropriate.

        :param method: one of 'get', 'post', 'put', 'delete'
        :param server_error_retries: set to the number of retries when encountering
        a pesky Server Error.
        :param ignore_codes: A list of pcloud error codes to treat as success.
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

        rx_dict = {}


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

        if raise_for_status == True:
            r.raise_for_status()

        return r, rx_dict


    @staticmethod
    def required_config_is_present(config_dir_path, account_name):
        return os.path.exists(_get_config_file_full_path(config_dir_path, account_name))


    def run_token_acquisition(self):
        self._config['auth'] = auth.get_access_tokens(
            YandexServerData.client_id,
            YandexServerData.client_secret
        )
        self._config['auth']['expires_at'] = \
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(self._config['auth']['expires_in']))
        self._save_config()


    def refresh_token(self):
        logger.info('Refresing Yandex access token...')

        res_dict = auth.refresh_token(
            YandexServerData.client_id,
            YandexServerData.client_secret,
            self._config['auth']['refresh_token'])

        self._config['auth'].update(res_dict)
        self._config['auth']['expires_at'] = \
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(res_dict['expires_in']))

        self._save_config()


    def revoke_token(self):
        logger.warning('Revoke token not implemented for Yandex')


    def _get_item_metadata(self, item_id):
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'resources/{}'.format(item_id)])
        )

        print(rx_dict)

    def get_root_file_tree(self, root_folder_path=''):
        """
        This is a generator function. Each iteration returned will be an instance
        of StoreTree - this instance will just show the progress. Just use the last
        one returned for a complete tree.

        :param root_folder_path: the path to the root folder of the desired store.
        :return: StoreTree instance.
        """

        offset = 0

        while offset is not None:
            r, rx_dict = self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'resources/files']),
                params={'limit': 100, 'offset': offset}
                )

            print(rx_dict['items'])
            if 'items' in rx_dict and len(rx_dict['items']) > 0:
                offset = rx_dict['offset'] + len(rx_dict['items'])
            else:
                offset = None


if __name__ == '__main__':
    YandexServerData.set_to_yandex_server()
    d = YandexDrive('smlgit', os.getcwd(), '')
