import argparse
import os
import logging
import getpass
import sync_drives.sync as sync
from common.basic_utils import check_for_user_quit
from providers.google.server_metadata import GoogleServerData


def main(args):

    logging.basicConfig(level=logging.INFO)

    # Set server addresses
    GoogleServerData.set_to_google_server()

    # Check that any initial authentication has been done:
    if sync.required_config_is_present(args.provider, args.cpath, args.user) is False:
        print('It doesn\'t appear you have completed the required authentication '
              'step for {}'.format(args.provider))
        return

    print('Please enter your config file encryption password.')
    config_pw = getpass.getpass()

    print("Preparing to sync - press \'q\' then enter to stop the sync.")

    for res in sync.sync_drives(args.local_store_path, args.cpath,
                                [{'provider_name': args.provider,
                                  'user_id': args.user,
                                  'server_root_path': args.remote_store_path}],
                                config_pw):

        if check_for_user_quit() is True:
            break


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=
                                     'Compares the local store directory with the contents '
                                     'of the remote store and uploads/deletes files/directories '
                                     'as required.')

    parser.add_argument('provider', type=str, choices=sync.get_supported_provider_names(),
                        help='The name of the cloud drive provider.')
    parser.add_argument('user', type=str,
                        help='The account name that identifies you to the drive provider.')
    parser.add_argument('local_store_path', type=str,
                        help='The full path to the local store root directory.')
    parser.add_argument('remote_store_path', type=str,
                        help='The full path to the remote store root directory (relative to the drive root).')
    parser.add_argument('--cpath', type=str, default=os.getcwd(),
                        help='The full path to the directory that stores cloud-backup authentication'
                             'config files.')

    main(parser.parse_args())