"""
A script to back up files that have changed on the local store
to the specified cloud service.

Change is determined by modify time.
"""

import argparse
import os
import logging
import sync_drives.sync as sync
import providers.provider_list as provider_list
from common.basic_utils import check_for_user_quit


def main(args):

    logging.basicConfig(level=logging.INFO)

    # Init provider metadata
    provider_list.init_providers()

    # Check that any initial authentication has been done:
    if sync.required_config_is_present(args.provider, args.cpath, args.user) is False:
        print('It doesn\'t appear you have completed the required authentication '
              'step for {}'.format(args.provider))
        return

    print('==============================================================')
    print("Preparing to sync - press \'q\' then enter to stop the sync.")
    print('')

    for res in sync.sync_drives(args.local_store_path, args.cpath,
                                {'provider_name': args.provider,
                                  'user_id': args.user,
                                  'server_root_path': args.remote_store_path},
                                '',
                                analyse_only=args.analyse_only):

        if check_for_user_quit() is True:
            break

    print('==============================================================')
    print('')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=
                                     'Compares the local store directory with the contents '
                                     'of the remote store and uploads/deletes files/directories '
                                     'as required.')

    parser.add_argument('provider', type=str, choices=provider_list.get_supported_provider_names(),
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
    parser.add_argument('-a', action='store_true', dest='analyse_only',
                        help='If specified, only sync analysis is done, the actual sync isn\'t carried out.')

    main(parser.parse_args())