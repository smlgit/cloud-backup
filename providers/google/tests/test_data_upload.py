import datetime
import json
import os
import shutil
import unittest
from http.server import HTTPServer
from threading import Thread
import filecmp
import time

import common.test_utils as test_utils
import common.http_server_utils as http_server_utils
from providers.google.tests.test_common import GoogleTestBaseHandler
from providers.google.drive import GoogleDrive
from providers.google.server_metadata import GoogleServerData


def _cloud_server_thread(cloud_server_instance):
    cloud_server_instance.serve_forever()


class CreateFileHandler(GoogleTestBaseHandler):

    # =================================================================
    # Some class fields that the test cases can modify to set expected
    # requests and response data, and specify places to write data.

    server_file_create_dir_path = ''

    # If positive, will ignore a request to write to the file when this
    # byte is first seen, causing a need for the local to resend.
    ignore_write_request_at_byte_number = -1

    # If positive, will send a 503 when this byte is first seen, requiring
    # the local to request a resume.
    do_interrupt_error_at_byte_number = -1

    # If positive, will send a 403 when this byte is first seen, requiring
    # the local to restart the upload.
    do_restart_error_at_byte_number = -1


    # State vars
    written_bytes = 0
    last_written_content_range = ''

    @classmethod
    def init_for_new_upload(cls):
        CreateFileHandler.written_bytes = 0
        CreateFileHandler.last_written_content_range = ''
        setattr(CreateFileHandler, 'ignore_write_done', False)
        setattr(CreateFileHandler, 'interrupt_error_done', False)
        setattr(CreateFileHandler, 'restart_error_done', False)

    def do_POST(self):
        if self.testing_handle_google_token_refresh() is True:
            return

        rx_params = json.loads(self.rfile.read(int(self.headers['Content-Length'])).decode())
        setattr(CreateFileHandler, 'file_name', rx_params['name'])

        self.send_success_response(response_content_string=json.dumps({'id': '123456'}),
                                   extra_headers={'Location': http_server_utils.join_url_components([
                                       GoogleServerData.apis_domain, 'dummy_url'])})

    def do_PUT(self):

        if 'Content-Range' not in self.headers:
            self.send_error(400, 'Missing header Content-Range.')

        # If requesting a resume, the content range will look like "*/<total_length>"
        if (self.headers['Content-Range'][0] == '*' and
                int(self.headers['Content-Length']) == 0):

            extra_header = {}
            if self.last_written_content_range != '':
                extra_header = {'Range': 'bytes={}'.format(
                    CreateFileHandler.last_written_content_range.split()[1].split('/')[0])}

            self.send_success_response(extra_headers=extra_header, code=308)
            return

        # Get bytes sent data - "bytes <startbyte>-<endbyte>/totalbytes"
        start_byte = int(self.headers['Content-Range'].split()[1].split('/')[0].split('-')[0])
        end_byte = int(self.headers['Content-Range'].split()[1].split('/')[0].split('-')[1])
        total_bytes = int(self.headers['Content-Range'].split()[1].split('/')[1])

        # Check correct length
        content_length = int(self.headers['Content-Length'])

        if end_byte - start_byte + 1 != content_length:
            self.send_error(400, 'Content length {} doesn\'t match that in Content-Range header {}'.format(
                end_byte - start_byte + 1
            ))
            return

        # Send a restart error if requested
        if (CreateFileHandler.do_restart_error_at_byte_number > -1 and
                    CreateFileHandler.restart_error_done is False and
                    end_byte >= CreateFileHandler.do_restart_error_at_byte_number):
            CreateFileHandler.written_bytes = 0
            CreateFileHandler.last_written_content_range = ''

            server_file = os.path.join(CreateFileHandler.server_file_create_dir_path,
                                   CreateFileHandler.file_name)
            if os.path.exists(server_file):
                os.remove(server_file)

            CreateFileHandler.restart_error_done = True
            self.send_error(403)
            return

        # Send an interrupt error if requested
        if (CreateFileHandler.do_interrupt_error_at_byte_number > -1 and
                    CreateFileHandler.interrupt_error_done is False and
                    end_byte >= CreateFileHandler.do_interrupt_error_at_byte_number):
            CreateFileHandler.interrupt_error_done = True
            self.send_error(503)
            return

        # Ignore request if test requires it
        if (CreateFileHandler.ignore_write_request_at_byte_number < 0 or
                    end_byte < CreateFileHandler.ignore_write_request_at_byte_number or
                    CreateFileHandler.ignore_write_done is True):
            # Write file
            with open(os.path.join(CreateFileHandler.server_file_create_dir_path,
                                   CreateFileHandler.file_name), 'ab') as f:
                f.write(self.rfile.read(content_length))
                CreateFileHandler.written_bytes += content_length
                CreateFileHandler.last_written_content_range = self.headers['Content-Range']
        else:
            # Ignore request like it didn't happen
            CreateFileHandler.ignore_write_done = True

        if CreateFileHandler.written_bytes == total_bytes:
            self.send_success_response(
                    response_content_string=json.dumps({'id': 'dummy_file_id'}))
        else:
            # If haven't written anything yet, there is no mechanism to resume
            # because teh Range header can't be set to 0-0 (because byte 0 hasn't
            # been written. So in this case, send a redo:
            if CreateFileHandler.written_bytes == 0:
                self.send_error(403)
            else:
                # Success response is code 308 unless the upload is complete.
                self.send_success_response(
                    extra_headers={
                    'Range': 'bytes={}'.format(
                        CreateFileHandler.last_written_content_range.split()[1].split('/')[0])},
                code=308)


class TestDataUpload(unittest.TestCase):

    def _start_cloud_server(self, handler):
        self.cloud_server = HTTPServer(('', http_server_utils.find_free_port()), handler)
        GoogleServerData.set_to_own_server('http://127.0.0.1:{}'.format(self.cloud_server.server_port))

        Thread(target=_cloud_server_thread, args=(self.cloud_server,), daemon=True).start()

    def setUp(self):
        self.cloud_server = None
        self.test_data_root = os.path.join(os.getcwd(), 'cbackup_test')
        self.local_store_root = os.path.join(self.test_data_root, 'local_root')
        self.server_store_root = os.path.join(self.test_data_root, 'server_root')
        self.file256k_minus1_path = os.path.join(self.local_store_root, 'file256k_minus1.txt')
        self.file256k_path = os.path.join(self.local_store_root, 'file256k.txt')
        self.file256k_plus1_path = os.path.join(self.local_store_root, 'file256k_plus1.txt')
        self.file5M_path = os.path.join(self.local_store_root, 'file5M_.txt')
        self.file5M_plus1_path = os.path.join(self.local_store_root, 'file5M_plus1.txt')

        CreateFileHandler.init_for_new_upload()
        CreateFileHandler.server_file_create_dir_path = self.server_store_root
        CreateFileHandler.ignore_write_request_at_byte_number = -1
        CreateFileHandler.send_wait_error_at_byte_number = -1

        shutil.rmtree(self.server_store_root, ignore_errors=True)

        os.makedirs(self.test_data_root, exist_ok=True)
        os.makedirs(self.local_store_root, exist_ok=True)
        os.makedirs(self.server_store_root)

        # Make some random files
        test_utils.make_random_file(self.file256k_minus1_path, 256 * 1024 - 1, leave_existing=True)
        test_utils.make_random_file(self.file256k_path, 256 * 1024, leave_existing=True)
        test_utils.make_random_file(self.file256k_plus1_path, 256 * 1024 + 1, leave_existing=True)
        test_utils.make_random_file(self.file5M_path, 5 * 1048576, leave_existing=True)
        test_utils.make_random_file(self.file5M_plus1_path, 5 * 1048576 + 1, leave_existing=True)

    def tearDown(self):
        if self.cloud_server is not None:
            self.cloud_server.server_close()

    def testCreateFileNormal(self):
        self._start_cloud_server(CreateFileHandler)

        drive = GoogleDrive('local_test_acc', self.test_data_root, '')
        drive.create_file('defaultid', 'file256k_minus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_minus1_path)

        time.sleep(2)
        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_plus1_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file5M.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file5M_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_plus1_path)

        self.assertTrue(filecmp.cmp(
            self.file256k_path,
            os.path.join(self.server_store_root, 'file256k.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_minus1_path,
            os.path.join(self.server_store_root, 'file256k_minus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_plus1_path,
            os.path.join(self.server_store_root, 'file256k_plus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_path,
            os.path.join(self.server_store_root, 'file5M.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_plus1_path,
            os.path.join(self.server_store_root, 'file5M_plus1.txt'), shallow=False))


    def testCreateFileResend(self):
        self._start_cloud_server(CreateFileHandler)

        CreateFileHandler.ignore_write_request_at_byte_number = 200000

        drive = GoogleDrive('local_test_acc', self.test_data_root, '')
        drive.create_file('defaultid', 'file256k_minus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_minus1_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_plus1_path)

        CreateFileHandler.init_for_new_upload()
        CreateFileHandler.ignore_write_request_at_byte_number = 1000000

        drive.create_file('defaultid', 'file5M.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file5M_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_plus1_path)

        self.assertTrue(filecmp.cmp(
            self.file256k_path,
            os.path.join(self.server_store_root, 'file256k.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_minus1_path,
            os.path.join(self.server_store_root, 'file256k_minus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_plus1_path,
            os.path.join(self.server_store_root, 'file256k_plus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_path,
            os.path.join(self.server_store_root, 'file5M.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_plus1_path,
            os.path.join(self.server_store_root, 'file5M_plus1.txt'), shallow=False))


    def testCreateFile403Error(self):
        self._start_cloud_server(CreateFileHandler)

        CreateFileHandler.do_restart_error_at_byte_number = 200000

        drive = GoogleDrive('local_test_acc', self.test_data_root, '')
        drive.create_file('defaultid', 'file256k_minus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_minus1_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_plus1_path)

        CreateFileHandler.init_for_new_upload()
        CreateFileHandler.do_restart_error_at_byte_number = 3000000

        drive.create_file('defaultid', 'file5M.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file5M_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_plus1_path)

        self.assertTrue(filecmp.cmp(
            self.file256k_path,
            os.path.join(self.server_store_root, 'file256k.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_minus1_path,
            os.path.join(self.server_store_root, 'file256k_minus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_plus1_path,
            os.path.join(self.server_store_root, 'file256k_plus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_path,
            os.path.join(self.server_store_root, 'file5M.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_plus1_path,
            os.path.join(self.server_store_root, 'file5M_plus1.txt'), shallow=False))


    def testCreateFile503Error(self):
        self._start_cloud_server(CreateFileHandler)

        CreateFileHandler.do_interrupt_error_at_byte_number = 200000

        drive = GoogleDrive('local_test_acc', self.test_data_root, '')
        drive.create_file('defaultid', 'file256k_minus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_minus1_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file256k_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file256k_plus1_path)

        CreateFileHandler.init_for_new_upload()
        CreateFileHandler.do_interrupt_error_at_byte_number = 3000000

        drive.create_file('defaultid', 'file5M.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_path)

        CreateFileHandler.init_for_new_upload()
        drive.create_file('defaultid', 'file5M_plus1.txt',
                          modified_datetime=datetime.datetime.now(),
                          file_local_path=self.file5M_plus1_path)

        self.assertTrue(filecmp.cmp(
            self.file256k_path,
            os.path.join(self.server_store_root, 'file256k.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_minus1_path,
            os.path.join(self.server_store_root, 'file256k_minus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file256k_plus1_path,
            os.path.join(self.server_store_root, 'file256k_plus1.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_path,
            os.path.join(self.server_store_root, 'file5M.txt'), shallow=False))
        self.assertTrue(filecmp.cmp(
            self.file5M_plus1_path,
            os.path.join(self.server_store_root, 'file5M_plus1.txt'), shallow=False))
