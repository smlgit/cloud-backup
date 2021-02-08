import datetime
import json
import logging
import os
import time

import requests
from dateutil import parser as date_parser

import providers.google.auth as auth
from common import http_server_utils
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
    return dt.isoformat(dt).split('+')[0] + 'Z'


class GoogleDrive(object):

    def __init__(self, account_id, config_dir_path, config_pw):
        self._config = {'account_name': account_id}
        self._config_dir_path = config_dir_path
        self._config_pw = config_pw
        self._api_drive_endpoint_prefix = http_server_utils.join_url_components([GoogleServerData.apis_domain, 'drive/v3'])
        self._api_upload_endpoint_prefix = http_server_utils.join_url_components([GoogleServerData.apis_domain,
                                                                     'upload/drive/v3'])
        self._load_config(account_id)
        self._access_token_start_time = datetime.datetime(1970, 1, 1)

        # Try to refresh our token on start
        if 'auth' in self._config and 'refresh_token' in self._config['auth']:
            self.refresh_token()


    def _get_config_file_name(self):
        return self._config['account_name'] + '-cbconfig.data'


    def _get_config_file_full_path(self):
        return os.path.join(self._config_dir_path, self._get_config_file_name())


    def _save_config(self):
        with open(self._get_config_file_full_path(), 'w') as f:
            json.dump(self._config, f)


    def _load_config(self, account_name):
        if account_name == 'local_test_acc':
            # False credentials for local server testing
            self._config = {
                "account_name": account_name,
                "auth": {
                    "access_token": "local_test_access_token",
                    "refresh_token": "local_test_refresh_token",
                    "expires_in": 10000,
                    "scope": "https://www.googleapis.com/auth/drive",
                    "token_type": "Bearer"}
            }
        else:
            try:
                with open(self._get_config_file_full_path(), 'r') as f:
                    self._config = json.load(f)
            except:
                logger.warning('Failed to open google drive config file for account {}, '
                               'user will need to authenticate before accessing the drive.')
                self._config = {'account_name': account_name}


    def _get_auth_header(self):
        return 'Bearer ' + self._config['auth']['access_token']


    def _refresh_token_required(self):
        # refresh if we only have 5 minutes left
        return (self._access_token_start_time +
            datetime.timedelta(seconds=int(self._config['auth']['expires_in'])) <
            datetime.datetime.now())


    def _do_request(self, method, url, headers={}, params={}, data={}, json=None):
        """
        Does a standard requests.get call with the passed params but also:
            1. Checks to see if a token refresh is required
            2. Sets the authorization header

        :param method: one of 'get', 'post', 'put', 'delete'

        :return: whatever is returned from a requests call
        """
        if method == 'get': func = requests.get
        elif method == 'post': func = requests.post
        elif method == 'put': func = requests.put
        elif method == 'patch': func = requests.patch
        elif method == 'delete': func = requests.delete

        if self._refresh_token_required():
            self.refresh_token()

        headers['Authorization'] = self._get_auth_header()
        return func(url, headers=headers, params=params, data=data, json=json)


    def run_token_acquisition(self):
        self._config['auth'] = auth.get_access_tokens('https://www.googleapis.com/auth/drive',
                                                      GoogleServerData.client_id,
                                                      GoogleServerData.client_secret)
        self._save_config()
        self._access_token_start_time = datetime.datetime.now()


    def refresh_token(self):
        logger.info('Refresing google access token...')

        self._config['auth'].update(
            auth.refresh_token(GoogleServerData.client_id,
                               GoogleServerData.client_secret,
                               self._config['auth']['refresh_token']))
        self._access_token_start_time = datetime.datetime.now()
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
                                 [self._api_drive_endpoint_prefix, 'files', 'root']))
        r.raise_for_status()
        return r.json()


    def _get_file_metadata(self, file_id):
        r = self._do_request('get',
                             http_server_utils.join_url_components(
                                 [self._api_drive_endpoint_prefix, 'files', file_id]),
                             params={'fields': 'name, parents, modifiedTime'})
        r.raise_for_status()
        return r.json()


    def _get_drive_folder_tree(self):
        """
        :return: an instance of StoreTree representing the entire folder tree of the drive.
        """

        # Get the root id and create store tree
        root_id = self._get_root_folder()['id']
        result = StoreTree(id=root_id)

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
                                     params=params)
            r.raise_for_status()

            response_dict = r.json()

            for new_folder in response_dict['files']:
                result_folder = None

                # First check if the parent exists in the tree. If not, we'll
                # need to create it at the root level and update later.
                parent = result.find_item_by_id(new_folder['parents'][0])

                if parent is None:
                    result.add_folder(new_folder['parents'][0])

                # Now check if this folder has already been added as a parent
                # (that will mean it is at the top level). If so, move it to
                # its parent and update its name.
                try:
                    result.move_item(new_folder['id'], new_folder['parents'][0])
                    result.update_folder_name(new_folder['id'], new_folder['name'])
                except ValueError:
                    # New folder doesn't exist, create a new one.
                    result.add_folder(new_folder['id'], new_folder['name'],
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
                'fields': 'files/id, files/name, files/parents, files/modifiedTime',
                      'pageSize': 1000}
            if isinstance(response_dict, dict) and 'nextPageToken' in response_dict:
                params['pageToken'] = response_dict['nextPageToken']

            r = self._do_request('get', http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                                'files']),
                                     params=params)
            r.raise_for_status()
            response_dict = r.json()

            # For each file, add to tree
            for rx_file in response_dict['files']:
                tree.add_file(rx_file['id'],
                              rx_file['name'],
                              parent_id=rx_file['parents'][0],
                              modified_datetime=date_parser.isoparse(rx_file['modifiedTime']))

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
            })

        r.raise_for_status()
        return r.json()['id']


    def _wait_to_resume_upload(self, session_url, total_file_len, num_retries=5):
        """
        :param session_url:
        :param previous_retry_secs:
        :return: the start byte position to resume from if successful.
        Otherwise, one of <file_id> (operation complete), 'restart' or 'timeout'.
        """
        wait_time = 1.0
        retries = 0

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

                r = self._do_request('put', session_url,
                                     headers={'Content-Range': 'bytes {}-{}/{}'.format(
                                         current_pos, current_pos + num_to_send - 1, total_length
                                     )},
                                     data=f.read(num_to_send))

                if r.status_code == 403:
                    # Must restart
                    return previous_retry_secs * 2
                elif r.status_code in [502, 503, 504]:
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
                            return wa
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


    def create_file(self, parent_id, name, modified_datetime, file_local_path):
        """

        :param parent_id: The id of the new file's parent folder.
        :param name: The name to give the file on the remote server.
        :param modified_datetime: Modified time.
        :param file_local_path:
        :return: The id of the newly created file.
        """

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
                })

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
        modified_datetime = date_parser.isoparse(file_meta['modifiedTime'])

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

            with open(os.path.join(output_dir_path, output_filename), 'wb') as f:
                for chunk in r.iter_content(chunk_size=128):
                    f.write(chunk)


    def delete_item_by_id(self, item_id):
        r = self._do_request('delete', http_server_utils.join_url_components([self._api_drive_endpoint_prefix,
                                                               'files', item_id]))
        r.raise_for_status()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    GoogleServerData.set_to_google_server()
    d = GoogleDrive('smlgit100', os.getcwd(), '')

    # d.download_file_by_id('1Kd51Ig3UGwq6dtFvKjlgxfXb3i3ZrzwL',
    #                       os.path.join(os.getcwd()))

    # for i in d.get_root_file_tree(''):
    #     res = i
    # print(i._tree)

    # print(d.create_file('1wLI1Xk2Rnswsahd7GK-qSg3m1ztBMDvD', 'testfile.txt',
    #               datetime.datetime.utcnow(),
    #               os.path.join(os.getcwd(), 'cbackup_test/local_root', 'file256k_plus1.txt')))

    print(d.update_file('1rygRkPFaARjb2UJLz1JKWLUFVEFwWVCM', datetime.datetime.utcnow(),
                  os.path.join(os.getcwd(), 'cbackup_test/local_root', 'file256k.txt')))



