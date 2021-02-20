import unittest
import os
import shutil
import datetime
import common.config_utils as config_utils


class TestConfigUtils(unittest.TestCase):

    def setUp(self):
        self.test_dir = os.path.join(os.getcwd(), 'test_config_utils')
        shutil.rmtree(self.test_dir, ignore_errors=True)
        os.mkdir(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def testConfigStorage(self):
        config_file = os.path.join(self.test_dir, 'config_file.conf')
        pw = 'test_password'

        config_test_cases = [
            {},
            {'test1': 'sfafafa', 'test2': 34322323, 'test3': 5.678},
            {'test1': 'sfafafa', 'key_2': datetime.datetime.now(tz=datetime.timezone.utc)},
            {6: 'sfafafa', 'test2': 34322323, 28: 5.678}
        ]

        for test_config in config_test_cases:
            config_utils.save_config(test_config, config_file, pw)
            loaded_obj = config_utils.get_config(config_file, pw)
            self.assertEqual(test_config, loaded_obj,
                             msg='Saved: {} Loaded: {}'.format(test_config, loaded_obj))

    def testChangePassword(self):
        old_pw = 'old_pw'
        new_pw = 'new_passowrd_slightly_better'
        config_file = os.path.join(self.test_dir, 'config_file.conf')

        config_object = {'sfs': 'sfaffe', 'dt': datetime.datetime.now()}

        config_utils.save_config(config_object, config_file, old_pw)
        config_utils.change_config_password(config_file, old_pw, new_pw)

        self.assertEqual(config_object, config_utils.get_config(config_file, new_pw))

    def testWrongPassword(self):
        config_file = os.path.join(self.test_dir, 'config_file.conf')
        config_utils.save_config({'sfs': 'sfaffe', 'dt': datetime.datetime.now()},
                                 config_file, 'correct_pw')

        with self.assertRaises(ValueError):
            config_utils.get_config(config_file, 'wrong_password')