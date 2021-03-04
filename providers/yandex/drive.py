import datetime
import logging
import os
import time
import pathlib
import itertools

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
    return StoreTree.standardise_path(yandex_path.replace('disk:', '').lstrip('/'))


def _convert_standard_to_yandex_path(standard_path):
    return '/' + standard_path


def _yandex_id_from_yandex_path(yandex_path):
    return '/' + _convert_yandex_to_standard_path(yandex_path)


def _yandex_path_from_parent_id_and_name(parent_id, name):
    """

    :param parent_id: The Yandex id of the parent directory.
    :param name: name of the child.
    :return: string
    """
    return parent_id.rstrip('/') + '/' + name


def _concat_yandex_paths(p1, p2):
    return p1.rstrip('/') + '/' + p2


def _build_mtime_from_yandex_item(item_dict):
    if 'custom_properties' in item_dict and 'mtime_ns' in item_dict['custom_properties']:
        return datetime.datetime.fromtimestamp(item_dict['custom_properties']['mtime_ns'],
                                               tz=datetime.timezone.utc)

    return date_parser.isoparse(item_dict['modified'])


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
                    files={}, raise_for_status=True, stream=False):
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
        current_wait_time = 1
        max_retries = 5
        yandex_retry_codes = [500, 503]

        while retries < max_retries:
            headers['Authorization'] = self._get_auth_header()
            r = func(url, headers=headers, params=params, data=data, json=json, files=files,
                     stream=stream)

            # Check to see if there are errors in the response
            try:
                rx_dict = r.json()
            except:
                pass

            if r.status_code in yandex_retry_codes:
                logger.warning('Yandex send response code {}, will retry...'.format(r.status_code))
                time.sleep(current_wait_time)
                current_wait_time *= 2
                retries += 1
            else:
                break

        if raise_for_status == True:
            r.raise_for_status()

        return r, rx_dict


    def _wait_for_status_complete(self, url, request_type):
        """
        Will monitor the status url and return when a complete condition is met.

        :param url:
        :param request_type: as returned by the Yandex API.
        :return:
        """

        rx_dict = {'status': 'in-progress'}

        while 'status' in rx_dict and rx_dict['status'] != 'success':
            r, rx_dict = self._do_request(request_type.lower(), url)

            if r.status_code != 200:
                raise SystemError('Non 200 status code ( {} ) returned while waiting for '
                                  'operation to complete - url: {} , rx content: {}'.format(
                    r.status_code, url, r.content
                ))

            time.sleep(1)


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


    def _set_item_custom_mtime(self, item_path, modified_datetime):
        r, rx_dict = self._do_request(
            'patch',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'resources']),
            params={'path': item_path},
            json={'custom_properties': {'mtime_ns': modified_datetime.timestamp()}})


    def _get_item_metadata(self, item_path):

        result_dict = {}
        offset = 0

        while offset is not None:
            # 'fields' parameter doesn't appear to work...

            r, rx_dict = self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'resources']),
                params={'path': item_path, 'limit': 200, 'offset': offset},
            raise_for_status=False)

            if r.status_code == 404:
                # Item doesn't exist
                return None

            r.raise_for_status()

            if 'path' not in result_dict:
                # First response
                result_dict = rx_dict
            else:
                if '_embedded' in rx_dict:
                    # Append page of items to existing list
                    result_dict['_embedded']['items'] += rx_dict['_embedded']['items']

            if '_embedded' in rx_dict and len(rx_dict['_embedded']['items']) > 0:
                    offset = rx_dict['_embedded']['offset'] + len(rx_dict['_embedded']['items'])
            else:
                offset = None

        return result_dict


    def get_root_file_tree(self, root_folder_path=''):
        """
        This is a generator function. Each iteration returned will be an instance
        of StoreTree - this instance will just show the progress. Just use the last
        one returned for a complete tree.

        :param root_folder_path: the path to the root folder of the desired store.
        :return: StoreTree instance.
        """

        # Yandex uses paths only, so these are the ids.

        root_standard_path = StoreTree.standardise_path(root_folder_path)
        yandex_root_path = _convert_standard_to_yandex_path(root_standard_path)

        # Check the root path exists
        if self._get_item_metadata(yandex_root_path) is None:
            raise ValueError('Couldn\'t find folder with path {}'.format(root_standard_path))

        result_tree = StoreTree(id=yandex_root_path)

        # Yandex's resources/files request returns all files, but not directories.
        # This means we will miss empty directories...
        # So we have to traverse each directory individually using the resources
        # request. Slow.

        stack = [yandex_root_path]

        while len(stack) > 0:
            parent_yandex_path = stack.pop()
            parent_meta = self._get_item_metadata(parent_yandex_path)

            if '_embedded' in parent_meta and len(parent_meta['_embedded']['items']) > 0:

                # Add new dirs and files to parent
                for item in parent_meta['_embedded']['items']:
                    item_id = _yandex_id_from_yandex_path(item['path'])

                    if item['type'] == 'dir':
                        result_tree.add_folder(item_id,
                                               name=item['name'],
                                               parent_id=parent_yandex_path)
                        stack.append(item_id)
                    else:
                        result_tree.add_file(item_id,
                                             item['name'],
                                             parent_id=parent_yandex_path,
                                             modified_datetime=_build_mtime_from_yandex_item(item),
                                             file_hash=item['md5'])

            yield result_tree


    def create_folder(self, parent_id, name):
        """
        :param parent_id: parent folder id.
        :param name: name of new folder.
        :return: the id of the created folder.
        """
        r, rx_dict = self._do_request(
            'put',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'resources']),
            params={'path': _yandex_path_from_parent_id_and_name(parent_id, name)}
        )

        if r.status_code == 201:
            # Get metadata
            r, rx_dict = self._do_request(rx_dict['method'].lower(), rx_dict['href'])
            return _yandex_id_from_yandex_path(rx_dict['_embedded']['path'])
        else:
            raise SystemError('Unexpected result from create folder: {}'.format(r.status_code))


    def create_folder_by_path(self, folder_path):
        """
        Creates a folder as specfified by folder_path.
        Folders in the path are checked for existence and created if they aren't
        already.

        :param folder_path: path to new folder from the server root.
        :return: the id of the created folder.
        """
        result = None

        yandex_path = pathlib.Path(
            _convert_standard_to_yandex_path(StoreTree.standardise_path(folder_path))
        )
        current_parent = pathlib.Path('/')

        for folder_path in itertools.chain(reversed(yandex_path.parents), [yandex_path]):
            if folder_path != pathlib.Path('/'):

                # yandex screams if you try and create existing folder
                parent_data = self._get_item_metadata(current_parent)
                child_exists = False

                for child in parent_data['_embedded']['items']:
                    if child['type'] == 'dir' and child['name'] == folder_path.name:
                        child_exists = True
                        break

                if child_exists is False:
                    result = self.create_folder(str(current_parent), folder_path.name)

                current_parent = folder_path


        # Now get folder id if needed
        if result is None:
            result = _yandex_id_from_yandex_path(self._get_item_metadata(yandex_path)['path'])

        return result


    def create_file(self, parent_id, name, modified_datetime, file_local_path):
        """

        :param file_id: The id of the file to update.
        :param modified_datetime: Modified time.
        :param file_local_path:
        :return: New file id.
        """

        return self.update_file(_concat_yandex_paths(parent_id, name),
                                modified_datetime,
                                file_local_path)


    def update_file(self, file_id, modified_datetime, file_local_path):

        # Get upload url
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'resources/upload']),
            params={'path': file_id, 'overwrite': 'true'}
        )

        with open(file_local_path, 'rb') as f:
            r, rx_dict = self._do_request(rx_dict['method'].lower(), rx_dict['href'],
                                          data=f)


        # Now verify the upload
        file_meta = self._get_item_metadata(file_id)
        if file_meta['md5'] != hash_utils.calc_file_md5_hex_str(file_local_path):
            logger.error('Server md5 hash for file {} doesn\'t match local, deleting file on server.'.format(
                file_local_path
            ))
            self.delete_item_by_id(file_id)
            return None

        # Set mod timestamp
        self._set_item_custom_mtime(file_id, modified_datetime)

        return _yandex_id_from_yandex_path(file_meta['path'])


    def download_file_by_id(self, file_id, output_dir_path, output_filename=None):

        file_meta = self._get_item_metadata(file_id)

        if output_filename is None:
            output_filename = file_meta['name']

        output_file_path = os.path.join(output_dir_path, output_filename)

        # Get download url
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'resources/download']),
            params={'path': file_id}
        )

        # Do download
        r, rx_dict = self._do_request('get', rx_dict['href'], stream=True)

        with open(output_file_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)

        # Verify checksum and set modified time
        if file_meta['md5'] == hash_utils.calc_file_md5_hex_str(output_file_path):
            # Set modified time
            os.utime(output_file_path,
                     times=(datetime.datetime.now(tz=datetime.timezone.utc).timestamp(),
                            _build_mtime_from_yandex_item(file_meta).timestamp()))
        else:
            logger.error('Server md5 hash for file {} doesn\'t match local, deleting file on local.'.format(
                output_filename
            ))
            os.remove(output_file_path)


    def delete_item_by_id(self, item_id):
        r, rx_dict = self._do_request(
            'delete',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'resources']),
            params={'path': item_id}
        )

        if r.status_code == 202:
            self._wait_for_status_complete(rx_dict['href'], rx_dict['method'])


    def clear_trash(self):
        r, rx_dict = self._do_request(
            'delete',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'trash/resources']))

        if r.status_code == 202:
            self._wait_for_status_complete(rx_dict['href'], rx_dict['method'])


    @staticmethod
    def files_differ_on_hash(file_local_path, item_hash):
        return hash_utils.calc_file_md5_hex_str(file_local_path) != item_hash



