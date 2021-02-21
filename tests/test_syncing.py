import unittest
import os
import pathlib
import shutil
import logging
import datetime
import filecmp
from common import test_utils
from common import tree_utils
from sync_drives import sync
from providers.google.drive import GoogleDrive
from providers.google.server_metadata import GoogleServerData


def _files_timestamp_ns_equal(ts1, ts2):
    """
    Within 1 millisecond to be considered the same time (some
    providers only store to millisecond resolution).
    """
    if abs(ts1 - ts2) <= 1000000:
        return True

    return False

def _remove_dir_contents(dir_path):
    dir = pathlib.Path(dir_path)

    for child in dir.iterdir():
        if child.is_file():
            child.unlink()
        else:
            shutil.rmtree(str(child), ignore_errors=True)

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
                    self.assertTrue(filecmp.cmp(str(item), str(p2_item), shallow=False))
                    self.assertTrue(_files_timestamp_ns_equal(item.stat().st_mtime_ns, p2_item.stat().st_mtime_ns))

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
            """

            :param files_definition_list: list of {'name': , 'path': ,'size': ,} dicts.
            If size is negative, will make a directory.

            :return:
            """
            # Clear directories locally
            shutil.rmtree(self.test_local_dir, ignore_errors=True)
            shutil.rmtree(self.test_download_dir, ignore_errors=True)

            os.makedirs(self.test_root_dir, exist_ok=True)
            os.makedirs(self.test_local_dir, exist_ok=True)
            os.makedirs(self.test_download_dir, exist_ok=True)

            # Add files in specification
            for file_def in files_definition_list:
                os.makedirs(os.path.join(self.test_local_dir, file_def['path']), exist_ok=True)

                if file_def['size'] < 0:
                    os.makedirs(os.path.join(self.test_local_dir, file_def['path'], file_def['name']))
                else:
                    test_utils.make_random_file(os.path.join(
                        self.test_local_dir, file_def['path'], file_def['name']),
                        file_def['size'], leave_existing=False)

            # Clear server store
            drive = self.drive_class(self.account_id, self.config_file_dir, self.config_pw)
            server_tree = drive.get_root_folder_tree('')
            server_test_sandbox = server_tree.find_item_by_path(
                self.server_test_folder_parent_path,
                is_path_to_file=False)

            if server_test_sandbox is not None:
                drive.delete_item_by_id(server_test_sandbox['id'])

            # Create sandbox folder on server
            sandbox_id = drive.create_folder_by_path(self.server_test_folder_parent_path)

            # Create test root folder on server
            drive.create_folder(sandbox_id, self.server_test_folder_name)

            # Add a file to the test sandbox - this makes sure we are testing with
            # files on the drive that aren't related to the store itself.
            test_utils.make_random_file(os.path.join(
                self.test_root_dir, 'dummy_test_file.png'), 10)
            drive.create_file(sandbox_id, 'Dummy_file.png', datetime.datetime.utcnow(),
                                     os.path.join(self.test_root_dir, 'dummy_test_file.png'))

        def _download_store(self):
            _remove_dir_contents(self.test_download_dir)
            for res in sync.download_store(self.server_test_folder_path,
                                           self.provider_name,
                                           self.test_download_dir,
                                           self.account_id, self.config_file_dir,
                                           self.config_pw):
                pass

        def _sync_drives(self):
            for res in sync.sync_drives(self.test_local_dir,
                                        self.config_file_dir,
                                        {'provider_name': self.provider_name,
                                          'user_id': self.account_id,
                                          'server_root_path': self.server_test_folder_path},
                                        self.config_pw):
                pass

        @unittest.SkipTest
        def testSyncBasicFileModify(self):
            file_defs = [
                {'name': 'file_0_byte.txt', 'path': '','size': 0},
                {'name': 'file_1_byte.txt', 'path': '', 'size': 1},
                {'name': 'file_256k_minus 1_byte.txt', 'path': 'folder1', 'size': 256 * 1024 - 1},
                {'name': 'file_256k_byte.txt', 'path': 'folder1/folder2', 'size': 256 * 1024},

                # Empty directories
                {'name': 'empty_dir1', 'path': '', 'size': -1},
                {'name': 'empty_dir2', 'path': 'folder1/folder2', 'size': -1},
                {'name': 'empty_dir3', 'path': 'folder1', 'size': -1},
            ]

            # All new files
            self._setup_test_store(file_defs)

            self._sync_drives()
            self._download_store()
            self.assertDirectoriesAreEqual(self.test_local_dir, self.test_download_dir)

            # Modify a single file (data only) and redo (do for each file in list)
            for mod_file_def in file_defs:
                if mod_file_def['size'] >= 0:
                    test_utils.make_random_file(os.path.join(
                        self.test_local_dir, mod_file_def['path'], mod_file_def['name']),
                        mod_file_def['size'], leave_existing=False)

                    self._sync_drives()
                    self._download_store()
                    self.assertDirectoriesAreEqual(self.test_local_dir, self.test_download_dir)

            # Modify a single file (change size) and redo (do for each file in list)
            for mod_file_def in file_defs:
                if mod_file_def['size'] >= 0:
                    test_utils.make_random_file(os.path.join(
                        self.test_local_dir, mod_file_def['path'], mod_file_def['name']),
                        mod_file_def['size'] + 3, leave_existing=False)

                    self._sync_drives()
                    self._download_store()
                    self.assertDirectoriesAreEqual(self.test_local_dir, self.test_download_dir)

            # Remove all the files
            _remove_dir_contents(self.test_local_dir)
            self._sync_drives()
            self._download_store()
            self.assertDirectoriesAreEqual(self.test_local_dir, self.test_download_dir)

        def testDeleteItem(self):

            file_defs = [
                {'name': 'file_0_byte.txt', 'path': '', 'size': 0},
                {'name': 'file_1k_byte.txt', 'path': 'folder1', 'size': 1024},

                # Empty directories
                {'name': 'empty_dir1', 'path': '', 'size': -1},
                {'name': 'empty_dir2', 'path': 'folder1/folder2', 'size': -1},
            ]

            # For each item, load the store with the all the items and delete the
            # item and verify

            for file_def in file_defs:

                # All new files
                self._setup_test_store(file_defs)

                self._sync_drives()

                item_path = os.path.join(self.test_local_dir, file_def['path'], file_def['name'])

                if file_def['size'] < 0:
                    shutil.rmtree(item_path, ignore_errors=True)
                else:
                    os.remove(item_path)

                self._sync_drives()
                self._download_store()
                self.assertDirectoriesAreEqual(self.test_local_dir, self.test_download_dir)

class TestSyncingGoogleDrive(HiderClass.TestSyncing):

    def setUp(self):
        GoogleServerData.set_to_google_server()
        self.account_id = 'smlgit100'
        self.config_pw = 'smlgit100_test_password'
        self.provider_name = 'google'
        self.drive_class = GoogleDrive
        super(TestSyncingGoogleDrive, self).setUp()