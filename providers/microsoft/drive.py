import datetime
import logging
import os
import time

import requests
from urllib import parse as urlparser
from dateutil import parser as date_parser

import providers.microsoft.auth as auth
from common import http_server_utils
import common.config_utils as config_utils
from common.tree_utils import StoreTree
from providers.microsoft.server_metadata import MicrosoftServerData


logger = logging.getLogger(__name__)


_onedrive_scope = 'offline_access Files.ReadWrite.All'
_onedrive_batching_limt = 20


def _get_config_file_name(account_name):
    return account_name + '-ms-cbconfig.data'


def _get_config_file_full_path(config_dir_path, account_name):
    return os.path.join(config_dir_path, _get_config_file_name(account_name))


class OneDrive(object):
    def __init__(self, account_id, config_dir_path, config_pw):
        self._config = {'account_name': account_id}
        self._config_dir_path = config_dir_path
        self._config_pw = config_pw
        self._api_drive_endpoint_prefix = http_server_utils.join_url_components(
            [MicrosoftServerData.apis_domain, 'v1.0/me/drive'])
        self._api_drive_batch_url = http_server_utils.join_url_components(
            [MicrosoftServerData.apis_domain, 'v1.0/$batch'])
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
                    "refresh_token": "local_test_refresh_token",
                    "expires_at": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=10),
                    "scope": "https://www.googleapis.com/auth/drive",
                    "token_type": "Bearer"}
            }
        else:
            try:
                self._config = config_utils.get_config(
                    _get_config_file_full_path(self._config_dir_path,
                                               self._config['account_name']),
                    self._config_pw
                )
            except ValueError as err:
                # Probably password error, re-raise
                raise err
            except:
                logger.error('Failed to retrieve config data - ')
                logger.warning('Failed to open OneDrive config file for account {}, '
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

    def _do_request(self, method, url, headers={}, params={}, data={}, json=None):
        """
        Does a standard requests.get call with the passed params but also:
            1. Checks to see if a token refresh is required
            2. Sets the authorization header

        :param method: one of 'get', 'post', 'put', 'delete'
        :param error_500_retries: set to the number of retries when encountering
        Google's pesky 500 Server Error: Internal Server Error error.
        :return: whatever is returned from a requests call
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

        headers['Authorization'] = self._get_auth_header()
        r = func(url, headers=headers, params=params, data=data, json=json)

        if r.status_code == 429:
            j = r.json()
            print('Response returned too many requests:')
            print(j)

        return r

    def _batch_is_full(self, batch_dict):
        if 'requests' in batch_dict:
            return len(batch_dict['requests']) >= _onedrive_batching_limt

        return False

    def _add_request_to_batch(self, batch_dict, request_type, endpoint_url, params={}, body={}):

        if 'requests' not in batch_dict:
            batch_dict['requests'] = []

        if len(batch_dict['requests']) == 0:
            request_id = 1
        else:
            request_id = max(int(request['id']) for request in batch_dict['requests']) + 1

        new_request = {'id': request_id,
                       'method': request_type.upper(),
                       'url': endpoint_url}

        if len(params) > 0:
            new_request['url'] += '?{}'.format(urlparser.urlencode(params))

        if len(body) > 0:
            new_request['body'] = body

        batch_dict['requests'].append(new_request)
        return batch_dict

    @staticmethod
    def required_config_is_present(config_dir_path, account_name):
        return os.path.exists(_get_config_file_full_path(config_dir_path, account_name))

    def run_token_acquisition(self):
        self._config['auth'] = auth.get_access_tokens(_onedrive_scope,
                                                      MicrosoftServerData.client_id)
        self._config['auth']['expires_at'] = \
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(self._config['auth']['expires_in']))

        self._save_config()

    def refresh_token(self):
        logger.info('Refresing Microsoft access token...')

        res_dict = auth.refresh_token(
            _onedrive_scope,
            MicrosoftServerData.client_id,
            self._config['auth']['refresh_token'])

        print(res_dict)
        self._config['auth'].update(res_dict)
        self._config['auth']['expires_at'] =\
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(res_dict['expires_in']))

        self._save_config()

    def revoke_token(self):
        logger.warning('Revoke token not used on Microsoft - they refresh both '
                             'access AND refresh token.')

    def get_root_file_tree(self, root_folder_path=''):
        """
        This is a generator function. Each iteration returned will be an instance
        of StoreTree - this instance will just show the progress. Just use the last
        one returned for a complete tree.

        :param root_folder_path: the path to the root folder of the desired store.
        :return: StoreTree instance.
        """

        # Get root id
        root_folder_path = StoreTree.standardise_path(root_folder_path)

        if root_folder_path == '':
            url = http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix,
                                  'root'])
        else:
            url = http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix,
                                  'root:/{}'.format(StoreTree.standardise_path(root_folder_path))])
        r = self._do_request('get', url, params={'select': 'id'})
        r.raise_for_status()
        root_id = r.json()['id']

        result_tree = StoreTree(id=root_id)

        # Have to traverse the whole thing per directory, but can use
        # batching to help a little with latency...
        stack = [root_id]

        while len(stack) > 0:

            batch = {}

            # For each folder on the stack, build a request and put in the batch
            while len(stack) > 0 and self._batch_is_full(batch) == False:
                self._add_request_to_batch(
                    batch, 'GET',
                    '/me/drive/items/{}/children'.format(stack.pop()),
                    params={'select': 'id,name,folder,file,parentReference,lastModifiedDateTime'})

            rx_dict = None
            while rx_dict is None or '@odata.nextLink' in rx_dict:
                if rx_dict is not None and '@odata.nextLink' in rx_dict:
                    url = rx_dict['@odata.nextLink']
                    print('=============', url)
                else:
                    url = self._api_drive_batch_url


                r = self._do_request('post', url, json=batch)
                r.raise_for_status()

                rx_dict = r.json()

                for response in rx_dict['responses']:
                    if 'body' in response:
                        for item in response['body']['value']:
                            if 'folder' in item:
                                result_tree.add_folder(item['id'], name=item['name'],
                                                       parent_id=item['parentReference']['id'])
                                stack.append(item['id'])
                            else:
                                result_tree.add_file(item['id'], name=item['name'],
                                                     parent_id=item['parentReference']['id'],
                                                     modified_datetime=date_parser.isoparse(item['lastModifiedDateTime']))

                yield result_tree

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    MicrosoftServerData.set_to_microsoft_server()
    d = OneDrive('smlgit', os.getcwd(), '')
    #d.run_token_acquisition()

    for res in d.get_root_file_tree(''):
        tree = res
    print(tree._tree)