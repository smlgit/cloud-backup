import datetime
import logging
import os
import time

import requests
from dateutil import parser as date_parser

import providers.google.auth as auth
from common import http_server_utils
import common.config_utils as config_utils
from common.tree_utils import StoreTree
from providers.google.server_metadata import GoogleServerData


logger = logging.getLogger(__name__)


def get_byte_state_from_range_header(header_string):
    """
    Extracts the byte range currently complete from a Google Range header.

    :param header_string:
    :return: (start_byte, end_byte) - ints
    """
    # Format is bytes=<start>-<end>
    return (int(header_string.split('=')[1].split('-')[0]),
            int(header_string.split('=')[1].split('-')[1]))


def convert_dt_to_google_string(dt):
    return dt.isoformat().split('+')[0] + 'Z'


def convert_google_string_to_utc_datetime(s):
    return date_parser.isoparse(s)


def _get_config_file_name(account_name):
    return account_name + '-google-cbconfig.data'


def _get_config_file_full_path(config_dir_path, account_name):
    return os.path.join(config_dir_path, _get_config_file_name(account_name))


class GoogleDrive(object):
    def __init__(self, account_id, config_dir_path, config_pw):
        self._config = {'account_name': account_id}
        self._config_dir_path = config_dir_path
        self._config_pw = config_pw
        self._api_drive_endpoint_prefix = http_server_utils.join_url_components(
            [GoogleServerData.apis_domain, 'drive/v3'])
        self._api_upload_endpoint_prefix = http_server_utils.join_url_components([GoogleServerData.apis_domain,
                                                                                  'upload/drive/v3'])
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

                print(self._config['auth']['refresh_token'])
            except ValueError as err:
                # Probably password error, re-raise
                raise err
            except:
                logger.error('Failed to retrieve config data - ')
                logger.warning('Failed to open google drive config file for account {}, '
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
                    error_500_retries=0):
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

        retries = 0

        r = None
        current_sleep_time = 1

        while retries <= error_500_retries:
            headers['Authorization'] = self._get_auth_header()
            r = func(url, headers=headers, params=params, data=data, json=json)
            if r.status_code != 500:
                break

            logger.warning('Received an HTTP 500 error from the Google server...')
            time.sleep(current_sleep_time)
            retries += 1
            current_sleep_time *= 2

        return r

    @staticmethod
    def required_config_is_present(config_dir_path, account_name):
        return os.path.exists(_get_config_file_full_path(config_dir_path, account_name))

    def run_token_acquisition(self):
        self._config['auth'] = auth.get_access_tokens('https://www.googleapis.com/auth/drive',
                                                      GoogleServerData.client_id,
                                                      GoogleServerData.client_secret)
        self._config['auth']['expires_at'] = \
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(self._config['auth']['expires_in']))

        self._save_config()

    def refresh_token(self):
        logger.info('Refresing google access token...')

        res_dict = auth.refresh_token(
            GoogleServerData.client_id,
            GoogleServerData.client_secret,
            self._config['auth']['refresh_token'])

        self._config['auth'].update(res_dict)
        self._config['auth']['expires_at'] =\
            datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
                seconds=int(res_dict['expires_in']))

        self._save_config()

    def revoke_token(self):
        auth.revoke_token(self._config['auth']['access_token'])
        self._config['auth'] = {}
        self._save_config()

    def _get_root_folder(self):
        """
        :return: A {'id': , 'name': ,} dict representing the root folder.
        """
        r = self._do_request('get',
                             http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix, 'files', 'root']),
                             error_500_retries=5)
        r.raise_for_status()
        return r.json()

    def _get_file_metadata(self, file_id):
        r = self._do_request('get',
                             http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix, 'files', file_id]),
                             params={'fields': 'name, parents, modifiedTime'},
                             error_500_retries=5)
        r.raise_for_status()
        return r.json()

    def _get_drive_folder_tree(self):
        """
        :return: an instance of StoreTree representing the entire folder tree of the drive.
        """

        # Get the root id and create store tree
        root_id = self._get_root_folder()['id']
        result = StoreTree(id=root_id)

        # Google returns items randomly, only specifying the parent id.
        # We might not have received the parent item yet, so we maintain
        # a list of trees, the first being our result, the others are
        # "dangling" trees where the root item hasn't been received yet
        # but has been mentioned as a parent of an item that HAS been
        # received.
        tree_list = [result]

        response_dict = None
        while response_dict is None or 'nextPageToken' in response_dict:

            params = {
                'q': 'mimeType = \'application/vnd.google-apps.folder\' and trashed = false',
                'fields': 'files/id, files/name, files/parents',
                'pageSize': 1000}
            if isinstance(response_dict, dict) and 'nextPageToken' in response_dict:
                params['pageToken'] = response_dict['nextPageToken']

            r = self._do_request('get', http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                                               'files']),
                                 params=params,
                                 error_500_retries=5)
            r.raise_for_status()

            response_dict = r.json()

            for new_folder in response_dict['files']:

                # First check if the parent exists in one of the trees tree. If not, we'll
                # need to create it as the root of a new dangling tree and update later if/when
                # it arrives.
                parent_tree = None
                for tree in tree_list:
                    if tree.find_item_by_id(new_folder['parents'][0]) is not None:
                        parent_tree = tree
                        break

                if parent_tree is None:
                    parent_tree = StoreTree(id=new_folder['parents'][0])
                    tree_list.append(parent_tree)

                # Now check if this item has already been added as a parent
                # (that will mean it is a tree root). If so, move it to
                # its parent and update its name.
                added = False
                for tree_index in range(0, len(tree_list)):
                    tree = tree_list[tree_index]

                    if tree.root_id == new_folder['id']:
                        tree.update_folder_name(new_folder['id'],
                                                new_folder['name'])
                        parent_tree.add_tree(tree, new_folder['parents'][0])
                        del tree_list[tree_index]
                        added = True
                        break

                # New folder doesn't exist, create a new one.
                if added is False:
                    parent_tree.add_folder(new_folder['id'],
                                           new_folder['name'],
                                           new_folder['parents'][0])

        return result

    def get_root_folder_tree(self, root_folder_path=''):
        """

        :param root_folder_path: the path to the root folder of the desired store.

        :return: a StoreTree instance representing the drive folder structure starting
        from root_folder_path as root.
        """

        # Get complete folder tree
        complete = self._get_drive_folder_tree()
        if root_folder_path == '':
            return complete

        new_root = complete.find_item_by_path(root_folder_path)

        if new_root is None:
            raise ValueError('Couldn\'t find folder with path {}'.format(root_folder_path))

        return complete.create_new_from_id(new_root['id'])

    def get_root_file_tree(self, root_folder_path=''):
        """
        This is a generator function. Each iteration returned will be an instance
        of StoreTree - this instance will just show the progress. Just use the last
        one returned for a complete tree.

        :param root_folder_path: the path to the root folder of the desired store.
        :return: StoreTree instance.
        """

        # First get the folder tree
        tree = self.get_root_folder_tree(root_folder_path)

        # Get the files

        response_dict = None
        while response_dict is None or 'nextPageToken' in response_dict:

            params = {
                'q': 'mimeType != \'application/vnd.google-apps.folder\' and trashed = false',
                'fields': 'nextPageToken, files/id, files/name, files/parents, files/modifiedTime',
                'pageSize': 1000}
            if isinstance(response_dict, dict) and 'nextPageToken' in response_dict:
                params['pageToken'] = response_dict['nextPageToken']

            r = self._do_request('get', http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                                               'files']),
                                 params=params,
                                 error_500_retries=5)

            r.raise_for_status()
            response_dict = r.json()

            # For each file, add to tree
            for rx_file in response_dict['files']:

                # Need to check for this because shared files/folders from some other drive
                # can have no parents.
                # We only support the use of files/folders on our drive.
                if 'parents' in rx_file:

                    # Remember that our tree is now possibly cut down and only starts at some
                    # folder that isn't the drive root, so look for the parent first, and add
                    # only if found.
                    parent = tree.find_item_by_id(rx_file['parents'][0])

                    if parent is not None:
                        tree.add_file(rx_file['id'],
                                      rx_file['name'],
                                      parent_id=parent['id'],
                                      modified_datetime=convert_google_string_to_utc_datetime(rx_file['modifiedTime']))

            yield tree

    def create_folder(self, parent_id, name):
        """
        :param parent_id: parent folder id.
        :param name: name of new folder.
        :return: the id of the created folder.
        """

        r = self._do_request('post', http_server_utils.join_url_components(
            [self._api_drive_endpoint_prefix, 'files']),
                             json={
                                 'name': name,
                                 'mimeType': 'application/vnd.google-apps.folder',
                                 'parents': [parent_id]
                             },
            error_500_retries=5)

        r.raise_for_status()
        return r.json()['id']

    def create_folder_by_path(self, folder_path):
        """
        Creates a folder as specfified by parent_path.
        Folders in the path are checked for existence and created if they aren't
        already.

        :param folder_path: path to new folder from the server root.
        :return: the id of the created folder.
        """
        root_folder_tree = self.get_root_folder_tree()
        current_parent_id = root_folder_tree.find_item_by_path('', is_path_to_file=False)['id']

        path_folders = StoreTree.get_path_levels(folder_path)

        if path_folders[0] == '':
            return current_parent_id

        current_path = ''
        for folder_name in path_folders:
            new_parent = root_folder_tree.find_item_by_path(
                StoreTree.concat_paths([current_path, folder_name]))
            if new_parent is None:
                # Need to make on the server
                new_parent_id = self.create_folder(current_parent_id, folder_name)
                root_folder_tree.add_folder(new_parent_id, name=folder_name, parent_id=current_parent_id)
                current_parent_id = new_parent_id
            else:
                current_parent_id = new_parent['id']

            current_path = StoreTree.concat_paths([current_path, folder_name])

        return current_parent_id

    def _wait_to_resume_upload(self, session_url, total_file_len, num_retries=5):
        """
        :param session_url:
        :param previous_retry_secs:
        :return: the start byte position to resume from if successful.
        Otherwise, one of <file_id> (operation complete), 'restart' or 'timeout'.
        """
        wait_time = 1.0
        retries = 0

        logger.warning('Received an HTTP 5XX error from the Google server...')

        while retries < num_retries:
            time.sleep(wait_time)
            r = self._do_request('put', session_url,
                                 headers={'Content-Range': '*/{}'.format(total_file_len)})
            retries += 1
            wait_time *= 2

            if r.status_code in [200, 201]:
                return 'done'

            if r.status_code == 308:
                if 'Range' in r.headers:
                    new_start_byte = get_byte_state_from_range_header(r.headers['Range'])[1] + 1
                else:
                    new_start_byte = 0

                return new_start_byte

            if r.status_code == 404:
                return 'restart'

        return 'timeout'

    def _upload_file_data(self, session_url, file_path, previous_retry_secs=0.5):
        """
        Does a file upload after a session url has been acquired.
        This function will return True if the upload succeeds.

        If a retry is required, a new session url is required and
        a sleep is also required. In these cases, an integer will
        be returned - sleep for this amount of time, get a new session
        url and recall this function with the previous_retry_secs parameter
        set to the same value that was initially returned.

        :param session_url:
        :param file_path:
        :return:
        """
        send_in_multiples_of = 256 * 1024
        max_multiples = 10

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

                # If uploading a zero length file, we just send a put request with no range or data.
                if total_length == 0:
                    header = {}
                    data = {}
                else:
                    header = {'Content-Range': 'bytes {}-{}/{}'.format(
                        current_pos, current_pos + num_to_send - 1, total_length)}
                    data = f.read(num_to_send)

                r = self._do_request('put', session_url, headers=header, data=data)

                if r.status_code == 403:
                    # Must restart
                    return previous_retry_secs * 2
                elif r.status_code >= 500 and r.status_code < 600:
                    # Some sort of network interuption. Try and resume
                    wait_result = self._wait_to_resume_upload(session_url, total_length)

                    if isinstance(wait_result, int):
                        current_pos = wait_result
                    else:
                        if wait_result == 'restart':
                            return 1.0
                        elif wait_result == 'timeout':
                            raise ConnectionError('Failed to upload data for file {} to Google drive.'.format(
                                file_path
                            ))
                        else:
                            # Should be a file id
                            return wait_result
                elif r.status_code != 200 and r.status_code != 201 and r.status_code != 308:
                    r.raise_for_status()
                else:
                    # Appears to be ok. Check if we are done.

                    if 'Range' in r.headers:
                        # Need to send starting from position specified in Range header
                        # Response Range format: previous <startbyte>-<endbyte>/totalbytes
                        current_pos = get_byte_state_from_range_header(r.headers['Range'])[1] + 1
                    else:
                        current_pos += num_to_send

                    if current_pos >= total_length:
                        if r.status_code != 200 and r.status_code != 201:
                            raise SystemError(
                                'All bytes transfered to Google drive but didn\'t receive a success code.')
                        return r.json()['id']

                f.seek(current_pos)

    def create_empty_file(self, parent_id, name, modified_datetime):
        """

        :param parent_id: The id of the new file's parent folder.
        :param name: The name to give the file on the remote server.
        :param modified_datetime: Modified time.
        :return: The id of the newly created file.
        """

        r = self._do_request('post',
                             http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix, 'files']),
                             params={'fields': 'id'},
                             json={
                                 'name': name,
                                 'modifiedTime': convert_dt_to_google_string(modified_datetime),
                                 'parents': [parent_id]
                             },
                             error_500_retries=5)

        r.raise_for_status()
        return r.json()['id']

    def create_file(self, parent_id, name, modified_datetime, file_local_path):
        """

        :param parent_id: The id of the new file's parent folder.
        :param name: The name to give the file on the remote server.
        :param modified_datetime: Modified time.
        :param file_local_path:
        :return: The id of the newly created file.
        """

        if os.stat(file_local_path).st_size == 0:
            return self.create_empty_file(parent_id, name, modified_datetime)

        retries = 0
        retry_sleep = 0.5

        while retries < 10:
            r = self._do_request('post', http_server_utils.join_url_components(
                [self._api_upload_endpoint_prefix, 'files']),
                                 params={'uploadType': 'resumable', 'fields': 'id'},
                                 json={
                                     'name': name,
                                     'modifiedTime': convert_dt_to_google_string(modified_datetime),
                                     'parents': [parent_id]
                                 },
                             error_500_retries=5)

            r.raise_for_status()

            session_url = r.headers['Location']

            res = self._upload_file_data(session_url, file_local_path,
                                         previous_retry_secs=retry_sleep)
            if isinstance(res, str) is True:
                return res

            retry_sleep = res
            time.sleep(res)
            retries += 1

        raise ConnectionError('Too many retries for file upload')

    def update_file(self, file_id, modified_datetime, file_local_path):
        """

        :param file_id: The id of the file to update.
        :param modified_datetime: Modified time.
        :param file_local_path:
        :return: True if successful.
        """

        retries = 0
        retry_sleep = 0.5

        while retries < 10:
            r = self._do_request('patch', http_server_utils.join_url_components(
                [self._api_upload_endpoint_prefix, 'files', file_id]),
                                 params={'uploadType': 'resumable'},
                                 json={
                                     'modifiedTime': convert_dt_to_google_string(modified_datetime)
                                 })

            r.raise_for_status()

            session_url = r.headers['Location']

            res = self._upload_file_data(session_url, file_local_path,
                                         previous_retry_secs=retry_sleep)
            if isinstance(res, str):
                return True

            retry_sleep = res
            time.sleep(res)
            retries += 1

        raise ConnectionError('Too many retries for file upload')

    def download_file_by_id(self, file_id, output_dir_path, output_filename=None):
        # Get the modified time and name
        file_meta = self._get_file_metadata(file_id)
        if output_filename is None:
            output_filename = file_meta['name']

        # Download the data
        # Special requests mode for streaming large files

        if self._refresh_token_required():
            self.refresh_token()

        with requests.get(
                http_server_utils.join_url_components(
                    [self._api_drive_endpoint_prefix, 'files', file_id]),
                headers={'Authorization': self._get_auth_header()},
                params={'alt': 'media'}) as r:
            r.raise_for_status()

            os.makedirs(output_dir_path, exist_ok=True)

            with open(os.path.join(output_dir_path, output_filename), 'wb') as f:
                for chunk in r.iter_content(chunk_size=128):
                    f.write(chunk)

            # Set modified time
            os.utime(os.path.join(output_dir_path, output_filename),
                     times=(datetime.datetime.utcnow().timestamp(),
                            convert_google_string_to_utc_datetime(file_meta['modifiedTime']).timestamp()))

    def delete_item_by_id(self, item_id):
        r = self._do_request('delete', http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                                              'files', item_id]),
                             error_500_retries=5)
        r.raise_for_status()

