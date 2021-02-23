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


def _convert_dt_to_onedrive_string(dt):
    return dt.isoformat().split('+')[0] + 'Z'


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


    def _do_request(self, method, url, headers={}, params={}, data={}, json=None,
                    error_500_retries=0, omit_auth_header=False):
        """
        Does a standard requests call with the passed params but also:
            1. Checks to see if a token refresh is required
            2. Sets the authorization header

        :param method: one of 'get', 'post', 'put', 'delete'
        :param error_500_retries: set to the number of retries when encountering
        a pesky 5XX Server Error.
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

        retries = 0

        r = None
        current_sleep_time = 1

        while retries <= error_500_retries:

            if omit_auth_header == False:
                headers['Authorization'] = self._get_auth_header()
            r = func(url, headers=headers, params=params, data=data, json=json)
            if r.status_code != 500:
                break

            logger.warning('Received an HTTP 500 error from the Google server...')
            time.sleep(current_sleep_time)
            retries += 1
            current_sleep_time *= 2

        if r.status_code == 429:
            j = r.json()
            print('Response returned too many requests:')
            print(j)

        try:
            j = r.json()
            if 'error' in j:
                logger.warning('Error from OneDrive: {} - {}'.format(
                    j['error']['code'], j['error']['message']))
        except:
            pass

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

    def _get_file_metadata(self, item_id):
        r = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'items/{}'.format(item_id)]),
            params={'select': 'id,name,lastModifiedDateTime'})
        r.raise_for_status()
        return r.json()


    def _upload_file(self, parent_id, file_path, file_name, modified_datetime):
        # Create an upload session
        r = self._do_request(
            'post',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'items/{}:/{}:/createUploadSession'.format(
                    parent_id, file_name)]),
            json={
                "name": file_name,
                "lastModifiedDateTime": _convert_dt_to_onedrive_string(modified_datetime) })

        r.raise_for_status()

        upload_url = r.json()['uploadUrl']

        send_in_multiples_of = 320 * 1024
        max_multiples = 15

        total_length = os.stat(file_path).st_size
        current_pos = 0

        with open(file_path, mode='rb') as f:
            while True:
                left_to_send = total_length - current_pos

                if (left_to_send // send_in_multiples_of) >= max_multiples:
                    num_to_send = send_in_multiples_of * max_multiples
                else:
                    num_to_send = (left_to_send // send_in_multiples_of) * send_in_multiples_of
                    if num_to_send == 0:
                        num_to_send = left_to_send % send_in_multiples_of

                header = {'Content-Range': 'bytes {}-{}/{}'.format(
                    current_pos, current_pos + num_to_send - 1, total_length)}
                data = f.read(num_to_send)

                r = self._do_request('put', upload_url, headers=header,
                                     data=data, error_500_retries=10,
                                     omit_auth_header=True)
                r.raise_for_status()
                rx_dict = r.json()

                if 'nextExpectedRanges' in rx_dict:
                    current_pos = int(rx_dict['nextExpectedRanges'][0].split('-'))
                elif r.status_code == 200 or r.status_code == 201:
                    # Success
                    return rx_dict['id']
                else:
                    raise SystemError('Upload response from OneDrive wasn\'t didn\'t '
                                      'include expected ranges item')




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

    def create_folder(self, parent_id, name):
        """
        :param parent_id: parent folder id.
        :param name: name of new folder.
        :return: the id of the created folder.
        """
        r = self._do_request(
            'post',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'items/{}/children'.format(parent_id)]),
            json={"name": name, "folder": {} })

        r.raise_for_status()
        return r.json()['id']

    def delete_item_by_id(self, item_id):
        r = self._do_request('delete',
                             http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix,
                                  'items/{}'.format(item_id)]
                             ))
        r.raise_for_status()

    def download_file_by_id(self, file_id, output_dir_path, output_filename=None):
        # Get the modified time and name
        file_meta = self._get_file_metadata(file_id)
        if output_filename is None:
            output_filename = file_meta['name']

        # Get download url
        # r = self._do_request('get',
        #     http_server_utils.join_url_components(
        #         [self._api_drive_endpoint_prefix, 'items/{}/content'.format(file_id)]))
        # r.raise_for_status()
        #
        # if r.status_code != 302:
        #     print(r.content)
        #     raise SystemError('Couldn\'t initiate download from OneDrive')

        url = http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'items/{}/content'.format(file_id)])

        # Download the data
        # Special requests mode for streaming large files

        if self._refresh_token_required():
            self.refresh_token()

        with requests.get(url,
                          headers={'Authorization': self._get_auth_header()},) as r:
            r.raise_for_status()
            os.makedirs(output_dir_path, exist_ok=True)

            with open(os.path.join(output_dir_path, output_filename), 'wb') as f:
                for chunk in r.iter_content(chunk_size=128):
                    f.write(chunk)

            # Set modified time
            os.utime(os.path.join(output_dir_path, output_filename),
                     times=(datetime.datetime.utcnow().timestamp(),
                            date_parser.isoparse(file_meta['lastModifiedDateTime']).timestamp()))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    MicrosoftServerData.set_to_microsoft_server()
    d = OneDrive('smlgit', os.getcwd(), '')
    #d.run_token_acquisition()

    id = d._upload_file('6F4A41C3EA05C074!101',
                        os.path.join(os.getcwd(), 'testfile.txt'),
                        'testfile2.txt',
                        datetime.datetime.now(tz=datetime.timezone.utc))
    print(id)
    d.download_file_by_id(id, os.getcwd(), 'new_testfile2.txt')