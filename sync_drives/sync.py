import os
from pathlib import Path
import datetime
from providers.google.drive import GoogleDrive
from common.tree_utils import StoreTree


_drive_implementations = {
    'google': GoogleDrive
}


def sync_drives(path_to_local_root, path_to_config_dir,
                providers_list, config_pw):
    """
    Will check every folder and file in path_to_local_root and, for every
    provider in providers_list, upload files that have been modified since
    the last upload and delete any files or folders that are no longer on
    the local root.

    :param path_to_local_root:
    :param path_to_config_dir: Directory that stores the config files for
    the providers.
    :param providers_list: A list of
        {'provider_name': , 'user_id' , 'server_root_path': ,} dicts.

    provider_name can be 'google', ... user_id is used to find the appropriate
    config file in path_to_config_dir - each provide can have its own config
    file format and info. server_root_path is the path on the cloud drive to
    the store root folder (relative to the drive root).
    :param config_pw: Password used to encrypt the config files.
    :return: Nothing.
    """
    if os.path.exists(path_to_local_root) is False:
        raise FileNotFoundError('Local store root {} does not exist.'.format(path_to_local_root))

    for provider_dict in providers_list:
        cloud_drive = _drive_implementations[provider_dict['provider_name']](
            provider_dict['user_id'], path_to_config_dir, config_pw)

        # Build remote tree
        server_tree =\
            cloud_drive.get_root_file_tree(root_folder_path=provider_dict['server_root_path'])

        # Now cycle through the local store root and do the following:
        #    1. for each folder, check the local contents are present on the server and
        #       if not, or if the file modified date is older on the server, upload to the server.
        #    2. for each folder, delete any folders or folders that are on the server but not
        #       on the local.
        #
        # NOTE: This assumes pathlib.Path.glob('**') returns parent directories before their children.
        local_root = Path(path_to_local_root)

        for item in local_root.glob('**'):
            relative_path = item.relative_to(local_root)
            parent_relative_path = item.parent.relative_to(local_root)

            if relative_path != '.':
                server_item =\
                    server_tree.find_item_by_path(relative_path, is_path_to_file=item.is_file())

                local_modified_time = datetime.datetime.utcfromtimestamp(item.stat().st_mtime)

                if server_item is None:
                    # Not on server, add it

                    parent_id = server_tree.find_item_by_path(
                        parent_relative_path, is_path_to_file=False)

                    if item.is_dir() is True:
                        new_id = cloud_drive.create_folder(item.name, parent_id)
                        server_tree.add_folder(new_id, name=item.name, parent_id=parent_id)
                    elif item.is_file() is True:
                        new_id = cloud_drive.create_file(parent_id, item.name, local_modified_time,
                                                         str(item))
                        server_tree.add_file(new_id, item.name, parent_id=parent_id,
                                             modified_datetime=local_modified_time)
                elif item.is_file():
                    # Is on the server. If a file, check date for update
                    server_item = server_tree.find_item_by_path(relative_path, is_path_to_file=True)

                    if local_modified_time > server_item['modified']:
                        cloud_drive.update_file(server_item['id'], local_modified_time,
                                                str(item))

            # For each folder on the local store (starting from the root itself),
            # check if there are any files or folders on the server tree that don't
            # exist on the local (this works because both locations are guaranteed
            # to have the root directory).

            if item.is_dir():
                server_folder = server_tree.find_item_by_path(relative_path, is_path_to_file=False)

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
                            cloud_drive.delete_item_by_id(server_child['id'])
                            server_tree.remove_item(server_child['id'])

