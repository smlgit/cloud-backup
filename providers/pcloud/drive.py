import datetime
import logging
import os
import time

import requests
from urllib import parse as urlparser
from dateutil import parser as date_parser

import providers.pcloud.auth as auth
from common import http_server_utils
import common.config_utils as config_utils
from common.tree_utils import StoreTree
from providers.pcloud.server_metadata import PcloudServerData


logger = logging.getLogger(__name__)


def _convert_dt_to_pcloud_string(dt):
    return dt.isoformat().split('+')[0]


def _convert_pcloud_string_to_dt(s):
    return date_parser.parse(s)


def _get_config_file_name(account_name):
    return account_name + '-pcloud-cbconfig.data'


def _get_config_file_full_path(config_dir_path, account_name):
    return os.path.join(config_dir_path, _get_config_file_name(account_name))


def _item_id_from_id_str(id_str):
    return int(id_str.replace('d', '').replace('f', ''))


def _pcloud_path_standardise(p):
    """
    Pcloud file paths relative to the root start with '/' .
    :param p:
    :return:
    """
    return '/' + p.strip('/')


class PcloudDrive(object):
    def __init__(self, account_id, config_dir_path, config_pw):
        self._config = {'account_name': account_id}
        self._config_dir_path = config_dir_path
        self._config_pw = config_pw
        self._api_drive_endpoint_prefix = None
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
                self._api_drive_endpoint_prefix = self._config['auth']['api_host_domain']
            except:
                logger.warning('Failed to open Pcloud config file for account {}, '
                               'user will need to authenticate before accessing the drive.'.format(
                    account_name
                ))
                self._config = {'account_name': account_name}

    def _get_auth_header(self):
        """"""
        return 'Bearer ' + self._config['auth']['access_token']


    def _do_request(self, method, url, headers={}, params={}, data={}, json=None,
                    server_error_retries=10, raise_for_status=True):
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

        rx_dict = {}

        retries = 0
        current_sleep_time = 1

        while True:

            headers['Authorization'] = self._get_auth_header()
            r = func(url, headers=headers, params=params, data=data, json=json)


            # Success
            if r.status_code > 199 and r.status_code < 300:
                # Check to see if there are errors in the response
                rx_dict = {}

                try:
                    rx_dict = r.json()
                except:
                    pass

            if 'result' in rx_dict and rx_dict['result'] != 0:
                logger.warning('Pcloud returned an error code {} with message: {}'.format(
                    rx_dict['result'], rx_dict['error']
                ))

                if retries > server_error_retries:
                    raise SystemError('Too many retries to Pcloud')

                if rx_dict['result'] > 3999 and rx_dict['result'] < 6000:

                    # Backoff required
                    logger.warning('Sleeping for {} seconds as a result of Pcloud request...'.format(
                        current_sleep_time))
                    time.sleep(current_sleep_time)
                    retries += 1
                    current_sleep_time *= 2
                elif rx_dict['result'] < 4000:
                    # User errors
                    raise ValueError('User error with request to Pcloud.')
                else:
                    # Error, but should be expected given the call type
                    break
            else:
                break

        if raise_for_status == True:
            r.raise_for_status()

        return r, rx_dict


    @staticmethod
    def required_config_is_present(config_dir_path, account_name):
        return os.path.exists(_get_config_file_full_path(config_dir_path, account_name))


    def run_token_acquisition(self):
        self._config['auth'] = auth.get_access_token(PcloudServerData.client_id)
        self._api_drive_endpoint_prefix = self._config['auth']['api_host_domain']
        self._save_config()


    def refresh_token(self):
        logger.warning('Access tokens currently don\'t expire on Pcloud.')


    def revoke_token(self):
        logger.warning('Revoke token not used on Microsoft - they refresh both '
                             'access AND refresh token.')


    def _get_root_metadata(self):
        """
        Returns the metadata dict for the root of the server drive.
        :return:
        """
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'listfolder']),
            params={'folderid': 0})
        return rx_dict['metadata']


    def _get_folder_path_metadata(self, folder_path):
        folder_path = _pcloud_path_standardise(folder_path)
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'listfolder']),
            params={'path': folder_path})

        return rx_dict['metadata']


    def get_root_file_tree(self, root_folder_path=''):
        """
        This is a generator function. Each iteration returned will be an instance
        of StoreTree - this instance will just show the progress. Just use the last
        one returned for a complete tree.

        :param root_folder_path: the path to the root folder of the desired store.
        :return: StoreTree instance.
        """
        root_folder_id = _item_id_from_id_str(self._get_folder_path_metadata(root_folder_path)['id'])
        result_tree = StoreTree(root_folder_id)

        # Recursive traverse of the root
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'listfolder']),
            params={'folderid': root_folder_id, 'recursive': 1})

        # DFS the resultant contents lists to build tree
        stack = [rx_dict['metadata']]

        while len(stack) > 0:
            parent_item = stack.pop()

            for item in parent_item['contents']:
                if item['isfolder']:
                    result_tree.add_folder(_item_id_from_id_str(item['id']),
                                           name=item['name'],
                                           parent_id=_item_id_from_id_str(parent_item['id']))
                    stack.append(item)
                else:
                    result_tree.add_file(_item_id_from_id_str(item['id']),
                                         name=item['name'],
                                         parent_id=_item_id_from_id_str(parent_item['id']),
                                         modified_datetime=_convert_pcloud_string_to_dt(item['modified']))

        return result_tree


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    PcloudServerData.set_to_pcloud_server()
    d = PcloudDrive('smlgit', os.getcwd(), '')

    print(d.get_root_file_tree()._tree)