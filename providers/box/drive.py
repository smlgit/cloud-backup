import datetime
import logging
import os
import time
import json
import base64

import requests
from requests_toolbelt import MultipartEncoder
from dateutil import parser as date_parser

import providers.box.auth as auth
from common import http_server_utils
import common.config_utils as config_utils
from common.tree_utils import StoreTree
import common.hash_utils as hash_utils
from providers.box.server_metadata import BoxServerData


logger = logging.getLogger(__name__)


_box_max_direct_upload_file_size = 21000000


_metadata_fields = 'id,name,type,content_modified_at,sha1'


# Box uses integers for file and folder ids, but apparently they may not be unique
# across folders-files. So we'll use the Pcloud system of prefixing an item id with
# 'd' (folder) and 'f' (file).
# So, generally, we use the prefix string id everywhere except direct requests to Box
# that require the integer ids.

_box_root_folder_id = 'd0'


def _integer_id_from_str_id(id_str):
    return int(id_str.replace('d', '').replace('f', ''))


def _str_id_from_file_integer_id(integer_id):
    return 'f' + str(integer_id)


def _str_id_from_folder_integer_id(integer_id):
    return 'd' + str(integer_id)


def _id_is_folder(str_id):
    """
    :param str_id: Must be a string id with 'f' or 'd' prefix.
    :return: True if the id represents a folder, False othewise.
    """
    return str_id[0].lower() == 'd'


def _convert_dt_to_pcloud_string(dt):
    # Box must see utc info. Have to assume this naive datetime represents UTC time.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)

    # Box doesn't like better than millisecond accuracy...
    return dt.replace(microsecond=0).isoformat()


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
        self._api_upload_endpoint_prefix = http_server_utils.join_url_components(
            [BoxServerData.upload_domain, 'api/2.0'])
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
                    files={}, server_error_retries=10, ignore_codes=[],
                    raise_for_status=True, stream=False):
        """
        Does a standard requests call with the passed params but also:
            1. Sets the authorization header
            2. Will check for server errors in the response and back off if
               needed or raise an exception if appropriate.
            3. Monitor the headers for 'retry-after' and wait accordingly.

        :param method: one of 'get', 'post', 'put', 'delete'
        :param server_error_retries: set to the number of retries when encountering
        a pesky Server Error.
        :param ignore_codes: A list of status error codes to treat as success.
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
            r = func(url, headers=headers, params=params, data=data, json=json, files=files, stream=stream)

            try:
                rx_dict = r.json()
            except:
                pass

            # Deliberate requests for retry are code 429. Box sometimes returns 500 too,
            # so we retry with both types.
            if r.status_code == 429 or r.status_code == 500 or 'retry-after' in r.headers:
                if 'retry-after' in r.headers:
                    current_sleep_time = r.headers['retry-after']
                else:
                    current_sleep_time *= 2

                if retries > server_error_retries:
                    raise SystemError('Too many retries to Box')

                logger.warning('Retrying after received error code {} from Box...'.format(r.status_code))
                retries += 1
            else:
                break

        if raise_for_status == True and r.status_code not in ignore_codes:
            if r.status_code < 200 or r.status_code > 299:
                logger.error('Box response error: {}'.format(rx_dict))
            r.raise_for_status()

        return r, rx_dict


    def _do_paginated_get(self, url, entries_key, headers={}, params={}, data={}, json={},
                          limit=200, server_error_retries=10):
        """
        Will do a _do_request (get) but apply the required pagination logic.

        :return: a list of the received entries.
        """

        result = []
        rx_dict = None

        while True:
            params['usemarker'] = 'true'
            params['limit'] = limit

            # First call has no marker
            if rx_dict is not None:
                params['marker'] = rx_dict['next_marker']

            r, rx_dict = self._do_request('get', url, headers=headers, params=params,
                                          data=data, json=json,
                                          server_error_retries=server_error_retries)
            result += rx_dict[entries_key]

            if ('next_marker' not in rx_dict or rx_dict['next_marker'] == 'null' or
                rx_dict['next_marker'] == ''):
                break

        return result


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


    def _get_folder_id_from_path(self, folder_path):
        """
        :param folder_path: folder path relative to server drive root.
        :return: id of folder metadata. None if the folder doesn't exist.
        """

        if StoreTree.standardise_path(folder_path) == '':
            return _box_root_folder_id

        parent_folder_id = _integer_id_from_str_id(_box_root_folder_id)

        for folder_name in StoreTree.get_path_levels(folder_path):

            # Get folders in parent folder, look for current folder
            entries =\
                self._do_paginated_get(
                    http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                           'folders/{}/items'.format(parent_folder_id)]),
                    'entries',
                params={'fields': 'id,name'})

            parent_folder_id = None

            for item in entries:
                if item['name'] == folder_name:
                    parent_folder_id = item['id']
                    break

            if parent_folder_id is None:
                return None

        return _str_id_from_folder_integer_id(parent_folder_id)


    def _get_file_meta(self, file_id):
        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                   'files/{}'.format(_integer_id_from_str_id(file_id))]),
            params={'fields': _metadata_fields})
        return rx_dict


    def _do_direct_upload(self, file_local_path, modified_datetime, parent_id=None, file_name=None,
                          file_id=None):
        """
        Either file_id must be set (file update) or parent_id AND file_name must be set (new file).
        """

        # Bog-standard requests doesn't appear to support having a dict/string second in
        # front of the file section. So we are using requests-toolkit - this also has the
        # benefit of streaming the upload data.

        attr_dict = {'content_modified_at': _convert_dt_to_pcloud_string(modified_datetime)}

        if parent_id is not None:
            attr_dict['parent'] = {'id': str(_integer_id_from_str_id(parent_id))}
        if file_name is not None:
            attr_dict['name'] = file_name

        with open(file_local_path, 'rb') as f:
            m_encoder = MultipartEncoder(fields={
                'attributes': json.dumps(attr_dict),
                'file': (str(file_name), f)
            })

            if file_id is None:
                url = http_server_utils.join_url_components([self._api_upload_endpoint_prefix,
                                                             'files/content'])
            else:
                url = http_server_utils.join_url_components([self._api_upload_endpoint_prefix,
                                                              'files/{}/content'.format(
                                                                  _integer_id_from_str_id(file_id))])
            r, rx_dict = self._do_request(
                'post',
                url,
                params={'fields': 'id,sha1'},
                data=m_encoder,
                headers={
                    'Content-Type': m_encoder.content_type,
                    'content-md5': hash_utils.calc_file_sha1_hex_str(file_local_path)})

        return _str_id_from_file_integer_id(rx_dict['entries'][0]['id'])


    def _do_chunked_upload(self, file_local_path, modified_datetime, parent_id=None, file_name=None,
                          file_id=None):
        """
        Either file_id must be set (file update) or parent_id AND file_name must be set (new file).
        """

        total_length = os.stat(file_local_path).st_size

        json_params = {'file_size': total_length}

        if file_id is not None:
            url = http_server_utils.join_url_components([self._api_upload_endpoint_prefix,
                                                         'files/{}/upload_sessions'.format(
                                                             _integer_id_from_str_id(file_id)
                                                         )])
        else:
            url = http_server_utils.join_url_components([self._api_upload_endpoint_prefix,
                                                         'files/upload_sessions'])
            json_params['folder_id'] = str(_integer_id_from_str_id(parent_id))
            json_params['file_name'] = file_name


        r, session_dict = self._do_request('post',url, json=json_params)

        current_position = 0
        result_parts = []

        with open(file_local_path, 'rb') as f:
            while True:
                chunk = f.read(session_dict['part_size'])
                sha1 = base64.b64encode(hash_utils.calc_str_sha1_bytes(chunk)).decode('ascii')

                r, rx_dict = self._do_request(
                    'put',
                    http_server_utils.join_url_components(
                        [self._api_upload_endpoint_prefix, 'files/upload_sessions/{}'.format(session_dict['id'])]),
                    headers={
                        'content-range': 'bytes {}-{}/{}'.format(
                            current_position, current_position + len(chunk) - 1, total_length),
                        'digest': 'sha={}'.format(sha1)},
                    data=chunk)

                result_parts.append(rx_dict['part'])
                current_position = rx_dict['part']['offset'] + rx_dict['part']['size']

                if current_position >= total_length:
                    break

        # Commit the upload
        sha1 = base64.b64encode(hash_utils.calc_file_sha1_bytes(file_local_path)).decode('ascii')
        r, rx_dict = self._do_request(
            'post',
            http_server_utils.join_url_components(
                [self._api_upload_endpoint_prefix, 'files/upload_sessions/{}/commit'.format(session_dict['id'])]),
            json={'parts': result_parts,
                  'attributes': {
                      'content_modified_at': _convert_dt_to_pcloud_string(modified_datetime)}
                  },
            headers={'digest': 'sha={}'.format(sha1)})

        return rx_dict['entries'][0]['id']


    def get_root_file_tree(self, root_folder_path=''):
        """
        This is a generator function. Each iteration returned will be an instance
        of StoreTree - this instance will just show the progress. Just use the last
        one returned for a complete tree.

        :param root_folder_path: the path to the root folder of the desired store.
        :return: StoreTree instance.
        """

        root_folder_id = self._get_folder_id_from_path(root_folder_path)

        if root_folder_path is None:
            raise ValueError('Root {} doesn\'t appear to exist.'.format(root_folder_path))


        result_tree = StoreTree(root_folder_id)

        # Another provider that forces us to traverse every folder...
        stack = [_integer_id_from_str_id(root_folder_id)]

        while len(stack) > 0:
            parent_folder_id = stack.pop()

            # Get folders in parent folder, look for current folder
            entries = \
                self._do_paginated_get(
                    http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                           'folders/{}/items'.format(parent_folder_id)]),
                    'entries',
                    params={'fields': _metadata_fields})

            for item in entries:
                if item['type'] == 'folder':
                    result_tree.add_folder(_str_id_from_folder_integer_id(item['id']),
                                           name=item['name'],
                                           parent_id=_str_id_from_folder_integer_id(parent_folder_id))
                    stack.append(item['id'])
                else:
                    result_tree.add_file(_str_id_from_file_integer_id(item['id']),
                                         name=item['name'],
                                         parent_id=_str_id_from_folder_integer_id(parent_folder_id),
                                         modified_datetime=date_parser.isoparse(item['content_modified_at']),
                                         file_hash=item['sha1'])

            yield result_tree


    def create_folder(self, parent_id, name):
        """
        :param parent_id: parent folder id.
        :param name: name of new folder.
        :return: the id of the created folder.
        """

        r, rx_dict = self._do_request(
            'post',
            http_server_utils.join_url_components([self._api_drive_endpoint_prefix, 'folders']),
            params={'fields': 'id'},
            json={'parent': {'id': _integer_id_from_str_id(parent_id)}, 'name': name},
        ignore_codes=[409])

        if r.status_code == 409 and rx_dict['code'] == 'item_name_in_use':
            return _str_id_from_folder_integer_id(rx_dict['context_info']['conflicts'][0]['id'])

        return _str_id_from_folder_integer_id(rx_dict['id'])


    def create_folder_by_path(self, folder_path):
        """
        Creates a folder as specfified by folder_path.
        Folders in the path are checked for existence and created if they aren't
        already.

        :param folder_path: path to new folder from the server root.
        :return: the id of the created folder.
        """

        if StoreTree.standardise_path(folder_path) == '':
            return _box_root_folder_id

        current_parent_id = _box_root_folder_id

        for folder_name in StoreTree.get_path_levels(folder_path):
            current_parent_id = self.create_folder(current_parent_id, folder_name)

        return current_parent_id


    def create_file(self, parent_id, name, modified_datetime, file_local_path):
        if os.stat(file_local_path).st_size > _box_max_direct_upload_file_size:
            return self._do_chunked_upload(file_local_path, modified_datetime,
                                           parent_id=parent_id, file_name=name)
        else:
            return self._do_direct_upload(file_local_path, modified_datetime,
                                          parent_id=parent_id, file_name=name)


    def update_file(self, file_id, modified_datetime, file_local_path):
        if os.stat(file_local_path).st_size > _box_max_direct_upload_file_size:
            return self._do_chunked_upload(file_local_path, modified_datetime,
                                           file_id=file_id)
        else:
            return self._do_direct_upload(file_local_path, modified_datetime,
                                          file_id=file_id)


    def download_file_by_id(self, file_id, output_dir_path, output_filename=None):
        file_meta = self._get_file_meta(file_id)

        if output_filename is None:
            output_filename = file_meta['name']

        output_file_path = os.path.join(output_dir_path, output_filename)

        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                   'files/{}/content'.format(_integer_id_from_str_id(file_id))]),
        stream=True)

        with open(output_file_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=128):
                f.write(chunk)

        # Set modified time
        os.utime(output_file_path,
                 times=(datetime.datetime.utcnow().timestamp(),
                        date_parser.isoparse(file_meta['content_modified_at']).timestamp()))


    def delete_item_by_id(self, item_id):
        if _id_is_folder(item_id):

            r, rx_dict = self._do_request(
                'delete',
                http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                       'folders/{}'.format(
                                                           _integer_id_from_str_id(item_id))]),
                params={'recursive': 'true'},
                ignore_codes=[503])
            if r.status_code == 503:
                logger.warning('Box is taking an extended time to delete folder {}.'.format(item_id))
        else:
            self._do_request(
                'delete',
                http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                       'files/{}'.format(
                                                           _integer_id_from_str_id(item_id))]))

    def clear_trash(self):
        entries_list = self._do_paginated_get(
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix,'folders/trash/items']),
            'entries',
        params={'fields': _metadata_fields})

        for item in entries_list:
            if item['type'] == 'folder':
                self._do_request(
                    'delete',
                    http_server_utils.join_url_components(
                        [self._api_drive_endpoint_prefix, 'folders/{}/trash'.format(item['id'])]))
            else:
                self._do_request(
                    'delete',
                    http_server_utils.join_url_components(
                        [self._api_drive_endpoint_prefix, 'files/{}/trash'.format(item['id'])]))


    @staticmethod
    def files_differ_on_hash(file_local_path, item_hash):
        return hash_utils.calc_file_sha1_hex_str(file_local_path) != item_hash
