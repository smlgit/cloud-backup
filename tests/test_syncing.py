import unittest
import os
import pathlib
import shutil
import logging
import datetime
import time
import filecmp
from common import test_utils
from common import tree_utils
from sync_drives import sync
from providers.google.drive import GoogleDrive
from providers.google.server_metadata import GoogleServerData


class HiderClass(object):

    class TestSyncing(unittest.TestCase):

        def assertDirectoriesAreEqual(self, dir1_path, dir2_path):
            """
            Will RECURSIVELY check that, for dir1 and dir2:
                1. There are the same number of files and folders in each directory
                2. Each directory and file is named the same
                3. Each file is equal

            :param dir1_path:
            :param dir2_path:
            :return:
            """
            p1 = pathlib.Path(dir1_path)
            p2 = pathlib.Path(dir2_path)

            # Same number of dirs/files
            self.assertEqual(len([0 for item in p1.glob('**/*')]),
                             len([0 for item in p2.glob('**/*')]))

            # Check each file
            for item in p1.glob('**/*'):
                if item.is_file():
                    p2_item = p2.joinpath(item.relative_to(p1))
                    self.assertTrue(p2_item.exists())

                    print(str(item), str(p2_item))
                    self.assertTrue(filecmp.cmp(str(item), str(p2_item), shallow=False))

        def setUp(self):
            logging.basicConfig(level=logging.INFO)

            self.config_file_dir = os.getcwd()

            self.test_root_dir = os.path.join(os.getcwd(), 'cbackup_test_dir')
            self.test_local_dir = os.path.join(self.test_root_dir, 'local')
            self.test_download_dir = os.path.join(self.test_root_dir, 'download')

            self.server_test_folder_parent_path = 'test_sandbox'
            self.server_test_folder_name = 'store'
            self.server_test_folder_path = \
                tree_utils.StoreTree.concat_paths([self.server_test_folder_parent_path,
                                                   self.server_test_folder_name])

        def _setup_test_store(self, files_definition_list):
            # Clear directories locally
            shutil.rmtree(self.test_local_dir, ignore_errors=True)
            shutil.rmtree(self.test_download_dir, ignore_errors=True)

            os.makedirs(self.test_root_dir, exist_ok=True)
            os.makedirs(self.test_local_dir, exist_ok=True)
            os.makedirs(self.test_download_dir, exist_ok=True)

            # Add files in specification
            for file_def in files_definition_list:
                os.makedirs(os.path.join(self.test_local_dir, file_def['path']), exist_ok=True)
                test_utils.make_random_file(os.path.join(
                    self.test_local_dir, file_def['path'], file_def['name']),
                    file_def['size'], leave_existing=False)

            # Clear server store
            server_drive = self.drive_class(self.account_id, self.config_file_dir, '')
            server_tree = server_drive.get_root_folder_tree('')
            server_test_sandbox = server_tree.find_item_by_path(
                self.server_test_folder_parent_path,
                is_path_to_file=False)

            if server_test_sandbox is not None:
                server_drive.delete_item_by_id(server_test_sandbox['id'])
                # Hmmmm, seem to have to delay after removing existing files, otherwise
                # getting the tree seems to have old artifacts in it...
                print('about to sleep')
                time.sleep(10)

            # Create sandbox folder on server
            sandbox_id = server_drive.create_folder_by_path(self.server_test_folder_parent_path)

            # Create test root folder on server
            server_drive.create_folder(sandbox_id, self.server_test_folder_name)

            # Add a file to the test sandbox - this makes sure we are testing with
            # files on the drive that aren't related to the store itself.
            test_utils.make_random_file(os.path.join(
                self.test_root_dir, 'dummy_test_file.png'), 10)
            server_drive.create_file(sandbox_id, 'Dummy_file.png', datetime.datetime.utcnow(),
                                     os.path.join(self.test_root_dir, 'dummy_test_file.png'))

        def testSync(self):
            self._setup_test_store(
                [
                    {'name': 'file_1_byte.txt', 'path': '', 'size': 1},
                    {'name': 'file_256k_minus 1_byte.txt', 'path': 'folder1', 'size': 256 * 1024 - 1},
                    {'name': 'file_256k_byte.txt', 'path': 'folder1/folder2', 'size': 256 * 1024}
                ]
            )

            for res in sync.sync_drives(self.test_local_dir,
                             self.config_file_dir,
                             [{'provider_name': self.provider_name,
                               'user_id': self.account_id,
                               'server_root_path': self.server_test_folder_path}],
                             ''):
                pass

            for res in sync.download_store(self.server_test_folder_path,
                                self.provider_name,
                                self.test_download_dir,
                                self.account_id, self.config_file_dir, ''):
                pass

            self.assertDirectoriesAreEqual(self.test_local_dir, self.test_download_dir)

class TestSyncingGoogleDrive(HiderClass.TestSyncing):

    def setUp(self):
        GoogleServerData.set_to_google_server()
        self.account_id = 'smlgit100'
        self.provider_name = 'google'
        self.drive_class = GoogleDrive
        super(TestSyncingGoogleDrive, self).setUp()