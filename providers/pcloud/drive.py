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
                    files={}, server_error_retries=10, raise_for_status=True,
                    session=None):
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

        call_object = requests if session is None else session

        if method == 'get':
            func = call_object.get
        elif method == 'post':
            func = call_object.post
        elif method == 'put':
            func = call_object.put
        elif method == 'patch':
            func = call_object.patch
        elif method == 'delete':
            func = call_object.delete

        rx_dict = {}

        retries = 0
        current_sleep_time = 1

        while True:

            headers['Authorization'] = self._get_auth_header()
            r = func(url, headers=headers, params=params, data=data, json=json, files=files)


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


    def _get_item_metadata(self, item_id):
        # Have to work out if a file or folder by doing this jiggery-pokery...
        try:
            r = requests.get(
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'stat']),
                headers={'Authorization': self._get_auth_header()},
                params={'fileid': item_id})

            return r.json()['metadata']
        except:
            r, rx_dict = self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'listfolder']),
                params={'folderid': item_id})

            return rx_dict['metadata']


    def _upload_file(self, file_local_path, parent_id, name, modified_datetime):

        if os.stat(file_local_path).st_size > 0:
            with open(file_local_path, 'rb') as f:
                r, rx_dict = self._do_request(
                    'put',
                    http_server_utils.join_url_components(
                        [self._api_drive_endpoint_prefix, 'uploadfile']),
                    params={'folderid': parent_id, 'filename': name, 'nopartial': 1,
                            'mtime': int(modified_datetime.timestamp())},
                    data=f)
        else:
            # Zero byte file
            # Can only get this to work using the post/multipart encoding method.
            r, rx_dict = self._do_request(
                'post',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'uploadfile']),
                params={'folderid': parent_id, 'filename': name, 'nopartial': 1,
                        'mtime': int(modified_datetime.timestamp())},
                files={'file': (name, '')})

        return _item_id_from_id_str(rx_dict['metadata'][0]['id'])


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

            yield result_tree


    def create_file(self, parent_id, name, modified_datetime, file_local_path):
        """

        :param file_id: The id of the file to update.
        :param modified_datetime: Modified time.
        :param file_local_path:
        :return: True if successful.
        """

        return self._upload_file(file_local_path, parent_id, name, modified_datetime)


    def update_file(self, file_id, modified_datetime, file_local_path):
        # Get parent id
        meta_dict = self._get_item_metadata(file_id)

        parent_id = int(meta_dict['parentfolderid'])
        name = meta_dict['name']

        return self._upload_file(file_local_path, parent_id, name, modified_datetime)


    def create_folder(self, parent_id, name):
        """
        :param parent_id: parent folder id.
        :param name: name of new folder.
        :return: the id of the created folder.
        """

        r, rx_dict = self._do_request(
            'get',
            http_server_utils.join_url_components(
                [self._api_drive_endpoint_prefix, 'createfolderifnotexists']),
            params={'folderid': parent_id, 'name': name})

        return _item_id_from_id_str(rx_dict['metadata']['id'])


    def create_folder_by_path(self, folder_path):
        """
        Creates a folder as specfified by folder_path.
        Folders in the path are checked for existence and created if they aren't
        already.

        :param folder_path: path to new folder from the server root.
        :return: the id of the created folder.
        """

        folder_path = _pcloud_path_standardise(folder_path)

        current_parent_id = _item_id_from_id_str(self._get_root_metadata()['id'])

        path_folders = StoreTree.get_path_levels(folder_path)

        if path_folders[0] == '':
            return current_parent_id

        for folder_name in path_folders:
            current_parent_id = self.create_folder(current_parent_id, folder_name)

        return current_parent_id


    def download_file_by_id(self, file_id, output_dir_path, output_filename=None):
        # Get the modified time and name
        file_meta = self._get_item_metadata(file_id)
        file_length = int(file_meta['size'])

        if output_filename is None:
            output_filename = file_meta['name']

        # Seems like we have to use low level file ops to do downloads.
        # This requires a file descriptor and this gets closed when the connection
        # closes, so we need to use a session.
        #
        with requests.Session() as session:

            # Open file descriptor
            r, rx_dict = self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'file_open']),
                params={'flags': 0, 'fileid': file_id},
            session=session)

            fd = rx_dict['fd']

            # Download the data

            with open(os.path.join(output_dir_path, output_filename), 'wb') as f:

                bytes_read = 0

                while bytes_read < file_length:
                    r, rx_dict = self._do_request(
                        'get',
                        http_server_utils.join_url_components(
                            [self._api_drive_endpoint_prefix, 'file_read']),
                        params={'fd': fd, 'count': 1048576},
                        session=session)

                    f.write(r.content)
                    bytes_read += len(r.content)

            # Close the file descriptor
            self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'file_close']),
                params={'fd': fd},
            session=session)

        # Set modified time
        os.utime(os.path.join(output_dir_path, output_filename),
                 times=(datetime.datetime.utcnow().timestamp(),
                        _convert_pcloud_string_to_dt(file_meta['modified']).timestamp()))


    def delete_item_by_id(self, item_id):
        # Work out if its a file or folder
        meta_dict = self._get_item_metadata(item_id)

        if meta_dict['isfolder'] == True:
            self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'deletefolderrecursive']),
                params={'folderid': item_id})
        else:
            self._do_request(
                'get',
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'deletefile']),
                params={'fileid': item_id})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    PcloudServerData.set_to_pcloud_server()
    d = PcloudDrive('smlgit', os.getcwd(), '')

    # print(d.create_file(0, 'zerobyte.txt', datetime.datetime.now(tz=datetime.timezone.utc),
    #                     os.path.join(os.getcwd(), 'zerobyte.txt')))
    # print(d.update_file(28415559278, datetime.datetime.now(tz=datetime.timezone.utc),
    #                     os.path.join(os.getcwd(), 'zerobyte.txt')))

    # for res in d.get_root_file_tree():
    #     t = res
    #
    # print(t._tree)

    print(d._get_item_metadata(8561599268))
    print(d._get_item_metadata(28411151775))

    # d.download_file_by_id(28411151775, os.getcwd(), 'testdown.txt')
    # print(d._get_file_metadata(28411151775))