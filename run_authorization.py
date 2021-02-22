import os
import argparse
import getpass
import providers.provider_list as provider_list


def main(args):

    # Init provider metadata
    provider_list.init_providers()

    drive_class = provider_list.get_drive_class(args.provider)

    if drive_class.required_config_is_present(args.cpath, args.user):
        print(
            'Config file for this provider and user already exists - this will '
            'redo authorization.')

    drive = drive_class(args.user, args.cpath, config_pw)
    drive.run_token_acquisition()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=
                                     'Run the authorization process for the given provider so that '
                                     'the sync scripts have access to the given user\'s cloud drive.')

    parser.add_argument('provider', type=str, choices=provider_list.get_supported_provider_names(),
                        help='The name of the cloud drive provider.')
    parser.add_argument('user', type=str,
                        help='The account name that identifies you to the drive provider.')
    parser.add_argument('--cpath', type=str, default=os.getcwd(),
                        help='The full path to the directory that will store cloud-backup authentication'
                             'config files.')

    main(parser.parse_args())