import os
import logging
import itertools
from pathlib import Path
import datetime
from common.tree_utils import StoreTree
import providers.provider_list as provider_list


logger = logging.getLogger(__name__)


def _files_dt_out_of_sync(local_mtime, server_mtime):
    """

    :param local_mtime: local time modified datetime.
    :param server_mtime: server time modified datetime.
    :return:
    """

    # Greater than one second constitutes out of sync.
    # Can't use exact equal because some providers can only
    # store to ms resolution.
    if (local_mtime - server_mtime) / datetime.timedelta(milliseconds=1) > 1000:
        return True

    return False


def required_config_is_present(provider_name, config_dir_path, account_name):
    return provider_list.get_drive_class(provider_name).required_config_is_present(
        config_dir_path, account_name
    )


def download_store(server_root_path, provider_name, local_dest_path,
                    server_user_id, path_to_config_dir, config_pw):
    cloud_drive = provider_list.get_drive_class(provider_name)(
        server_user_id, path_to_config_dir, config_pw)

    # Build remote tree
    for res in cloud_drive.get_root_file_tree(root_folder_path=server_root_path):
        server_tree = res

    # Step through items and download to local
    for item in server_tree.get_items_with_parent_path():
        item_dir_path = os.path.join(local_dest_path, item['parent_path'])

        if item['is_folder'] is True:
            os.makedirs(os.path.join(item_dir_path, item['name']), exist_ok=True)
        else:
            # Download the file from the server
            cloud_drive.download_file_by_id(item['id'], item_dir_path,
                                            output_filename=item['name'])

        logger.info('Downloaded file {} to {}'.format(
            item['name'], item_dir_path
        ))

        yield None


def sync_drives(path_to_local_root, path_to_config_dir,
                provider_dict, config_pw, analyse_only=False):
    """
    Will check every folder and file in path_to_local_root and, for every
    provider in providers_list, upload files that have been modified since
    the last upload and delete any files or folders that are no longer on
    the local root.

    :param path_to_local_root:
    :param path_to_config_dir: Directory that stores the config files for
    the providers.
    :param provider_dict: A {'provider_name': , 'user_id' , 'server_root_path': ,} dict.

    provider_name can be 'google', ... user_id is used to find the appropriate
    config file in path_to_config_dir - each provide can have its own config
    file format and info. server_root_path is the path on the cloud drive to
    the store root folder (relative to the drive root).
    :param config_pw: Password used to encrypt the config files.
    :return: Nothing.
    """
    if os.path.exists(path_to_local_root) is False:
        raise FileNotFoundError('Local store root {} does not exist.'.format(path_to_local_root))

    logging.info('Starting sync to {} drive for account {} and store {}'.format(
        provider_dict['provider_name'],
        provider_dict['user_id'],
        provider_dict['server_root_path']
    ))

    cloud_drive = provider_list.get_drive_class(provider_dict['provider_name'])(
        provider_dict['user_id'], path_to_config_dir, config_pw)

    # Build remote tree
    for res in cloud_drive.get_root_file_tree(root_folder_path=provider_dict['server_root_path']):
        server_tree = res

    # Now cycle through the local store root and do the following:
    #    1. for each folder, check the local contents are present on the server and
    #       if not, or if the file modified date is older on the server, upload to the server.
    #    2. for each folder, delete any folders or folders that are on the server but not
    #       on the local.
    #
    # NOTE: This assumes pathlib.Path.glob('**') returns parent directories before their children.
    local_root = Path(path_to_local_root)

    # This chaining will produce all items in the local root (recursive) AND the local root itself.
    # It is important we have the local root too for checking deleted items on
    # the local.
    for item in itertools.chain([local_root], local_root.glob('**/*')):
        relative_path = item.relative_to(local_root)

        if str(relative_path) != '.':

            parent_relative_path = item.parent.relative_to(local_root)

            server_item =\
                server_tree.find_item_by_path(str(relative_path), is_path_to_file=item.is_file())

            local_modified_time = datetime.datetime.fromtimestamp(
                item.stat().st_mtime, tz=datetime.timezone.utc)

            if server_item is None:
                # Not on server, add it

                if analyse_only is True:
                    logger.info('Would create item {}'.format(str(item)))
                else:
                    parent_id = server_tree.find_item_by_path(
                        str(parent_relative_path), is_path_to_file=False)['id']

                    if item.is_dir() is True:
                        logger.info('Creating folder {}'.format(str(item)))
                        new_id = cloud_drive.create_folder(parent_id, item.name)
                        server_tree.add_folder(new_id, name=item.name, parent_id=parent_id)
                    elif item.is_file() is True:
                        logger.info('Creating file {}'.format(str(item)))
                        new_id = cloud_drive.create_file(parent_id, item.name, local_modified_time,
                                                         str(item))
                        server_tree.add_file(new_id, item.name, parent_id=parent_id,
                                             modified_datetime=local_modified_time)
            elif item.is_file():
                # Is on the server. If a file, check date for update
                server_item = server_tree.find_item_by_path(str(relative_path), is_path_to_file=True)

                if _files_dt_out_of_sync(local_modified_time, server_item['modified']):
                    if analyse_only is True:
                        logger.info('Would upload file {} with id {}  {}  {}'.format(
                            str(item), server_item['id'],
                            local_modified_time, server_item['modified']
                        ))
                    else:
                        logger.info('Uploading file {} with id {}'.format(
                            str(item), server_item['id']
                        ))
                        cloud_drive.update_file(server_item['id'], local_modified_time,
                                                str(item))

        # For each folder on the local store (starting from the root itself),
        # check if there are any files or folders on the server tree that don't
        # exist on the local (this works because both locations are guaranteed
        # to have the root directory).

        if item.is_dir():
            server_folder = server_tree.find_item_by_path(str(relative_path),
                                                          is_path_to_file=False)

            if server_folder is not None:
                for server_child in (server_folder['folders'] + server_folder['files']):
                    exists_on_local = False

                    for local_child in item.iterdir():
                        if (local_child.name == server_child['name'] and
                            ((local_child.is_dir() and StoreTree.item_is_folder(server_child)) or
                                 (local_child.is_file() and not StoreTree.item_is_folder(server_child)))):
                            exists_on_local = True
                            break

                    if exists_on_local is False:
                        # Can it on the server

                        if analyse_only is True:
                            logger.info('Would delete item {} with id {} from server'.format(
                                server_child['name'], server_child['id']
                            ))
                        else:
                            logger.info('Deleting item {} with id {} from server'.format(
                                server_child['name'], server_child['id']
                            ))
                            cloud_drive.delete_item_by_id(server_child['id'])
                            server_tree.remove_item(server_child['id'])

        yield None

