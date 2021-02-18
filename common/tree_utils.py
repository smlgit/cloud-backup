import datetime
import copy

class StoreTree(object):
    """
    Represents the structure and metadata of a store on a cloud drive.

    Hmmmm, if I had known, I might have been able to use pathlib for this...
    """

    def __init__(self, id=None):
        self._tree = {'id': id, 'name': '', 'folders': [], 'files': []}

    @staticmethod
    def prepend_root(p):
        return '/' + p.lstrip('/')

    @staticmethod
    def concat_paths(path_list):
        if len(path_list) < 1: return ''

        current_path = StoreTree.standardise_path(path_list[0])

        for p in path_list[1:]:
            if current_path != '':
                current_path += '/'

            current_path += StoreTree.standardise_path(p)

        return current_path

    @staticmethod
    def standardise_path(p):
        """
        We use / instead of \, the root of the store is always '' .
        :param p: the path string to standarise.
        """
        if p == '/': return ''
        if p == '.': return ''

        return p.replace('\\', '/').strip('/')

    @staticmethod
    def get_path_levels(p):
        """
        Splits the path p into a list of folder names (and the file name if
        the path is to a file).

        :param p:
        :return: list of strings.
        """

        return StoreTree.standardise_path(p).split('/')

    @staticmethod
    def item_is_folder(item_dict):
        return 'folders' in item_dict or 'files' in item_dict

    def create_new_from_id(self, folder_id):
        """

        :param folder_id:
        :return: a new StoreTree instance where the root is the folder
        specified by folder_id.
        """
        new_root = self.find_item_by_id(folder_id)
        if new_root is None:
            raise ValueError('Couldn\'t find item {}'.format(folder_id))

        result = StoreTree(id=new_root['id'])
        result._tree['files'] = new_root['files']
        result._tree['folders'] = new_root['folders']

        return result

    def find_item_by_id(self, element_id):
        """
        :param element_id: the id of the folder or file to find.

        :return: the folder or file dict if found, None otherwise.
        Note that client callers shoudn't modify the result and should
        only access the {'folders': [{id: , 'name'}] , 'files': [{'id' , 'name': }]}
        elements.
        """

        stack = [self._tree]

        while len(stack) > 0:
            folder = stack.pop()
            if folder['id'] == element_id:
                return folder
            else:
                # check files
                if 'files' in folder:
                    for file in folder['files']:
                        if file['id'] == element_id:
                            return file

                # Still not found, put this folders folders on the stack
                for child in folder['folders']:
                    stack.append(child)

        return None

    def find_item_by_path(self, path, is_path_to_file=False):
        """
        :param path: the path string from the tree root to the item.
        :param is_path_to_file: Set to True if the item is a file.

        :return: the folder or file dict if found, None otherwise.
        Note that client callers shoudn't modify the result and should
        only access the {'folders': [{id: , 'name'}] , 'files': [{'id' , 'name': }]}
        elements.
        """

        path = StoreTree.standardise_path(path)
        if path == '':
            return self._tree

        level_names = StoreTree.get_path_levels(path)
        current_folder = self._tree

        # Step through required folders
        for folder_name in level_names[:len(level_names) - 1]:
            new_folder = None

            for folder in current_folder['folders']:
                if folder['name'] == folder_name:
                    new_folder = folder
                    break

            if new_folder is None:
                return None

            current_folder = new_folder

        # Got to the last level, check for the existence of the final file
        # or folder
        if is_path_to_file is True:
            key = 'files'
        else:
            key = 'folders'

        for f in current_folder[key]:
            if f['name'] == level_names[-1]:
                return f

        return None

    def find_item_parent_by_id(self, item_id):
        """
        :param item_id: the id of the child folder or file to find.

        :return: a (parent_dict, child_dict) tuple if found, None otherwise.

        Note that client callers shoudn't modify the result and should
        only access the {'folders': [{id: , 'name'}] , 'files': [{'id' , 'name': }]}
        elements.
        """

        stack = [self._tree]

        while len(stack) > 0:
            folder = stack.pop()

            for new_file in folder['files']:
                if new_file['id'] == item_id:
                    return folder, new_file

            for new_folder in folder['folders']:
                if new_folder['id'] == item_id:
                    return folder, new_folder
                else:
                    stack.append(new_folder)

        return None, None

    def add_folder(self, id, name=None, parent_id=None):
        parent = self._tree

        if parent_id is not None:
            parent = self.find_item_by_id(parent_id)
            if parent is None:
                raise ValueError('Couldn\'t find parent with id {} in tree'.format(parent_id))

        new_folder = {'id': id, 'folders': [], 'files': []}
        if name is not None:
            new_folder['name'] = name

        parent['folders'].append(new_folder)

    def add_file(self, id, name, parent_id=None, modified_datetime=datetime.datetime.now()):
        parent = self._tree

        if parent_id is not None:
            parent = self.find_item_by_id(parent_id)
            if parent is None:
                raise ValueError('Couldn\'t find parent with id {} in tree'.format(parent_id))

        parent['files'].append({'id': id, 'name': name, 'modified': modified_datetime})

    def update_folder_name(self, item_id, name):
        item = self.find_item_by_id(item_id)

        if item is not None:
            item['name'] = name

    def remove_item(self, item_id):
        """
        :param item_id: the id of the item to remove.
        :return: the item tree dict.
        """
        parent, _ = self.find_item_parent_by_id(item_id)
        if parent is None:
            raise ValueError('Couldn\'t find item {}'.format(item_id))

        for i in range(0, len(parent['folders'])):
            if parent['folders'][i]['id'] == item_id:
                return parent['folders'].pop(i)

        for i in range(0, len(parent['files'])):
            if parent['files'][i]['id'] == item_id:
                return parent['files'].pop(i)

        return None

    def move_item(self, item_id, new_parent_id):
        """
        Make sure the new parent ISN'T A CHILD of the item to move.

        :param item_id: the item to move.
        :param new_parent_id: the new parent of the item to move.

        """
        child = self.remove_item(item_id)
        if child is None:
            raise ValueError('Couldn\'t find item {}'.format(item_id))

        new_parent = self.find_item_by_id(new_parent_id)
        if new_parent is None:
            raise ValueError('Couldn\'t find item {}'.format(new_parent_id))

        if StoreTree.item_is_folder(child):
            new_parent['folders'].append(child)
        else:
            new_parent['files'].append(child)

    def get_file_paths_list(self, include_folders=False):
        """
        :return: a list of the paths of all files in the tree.
        Paths are relative to the tree root.
        """
        result = []

        # Depth first search to build file paths
        stack = [(self._tree, '')]

        while len(stack) > 0:
            current_folder_tup = stack.pop()
            current_folder = current_folder_tup[0]
            old_path = current_folder_tup[1]

            current_path = StoreTree.concat_paths([old_path, current_folder['name']])

            for file_def in current_folder['files']:
                result.append(StoreTree.concat_paths([current_path, file_def['name']]))

            for new_folder in current_folder['folders']:
                if include_folders is True:
                    result.append(StoreTree.concat_paths([current_path, new_folder['name']]))

                stack.append((new_folder, current_path))

        return result

    def get_items(self):
        """
        :return: a generator - each result is a {'id': , 'name': , 'parent_path': , is_folder: ,}
        dict. The 'modified' key/value pair is included for files.
        Paths are the parent folder path and are relative to the tree root.
        Any directory returned is guaranteed to be returned before any of its children.
        """

        # Depth first search to build file paths
        stack = [(self._tree, '')]

        while len(stack) > 0:
            current_folder_tup = stack.pop()
            current_folder = current_folder_tup[0]
            old_path = current_folder_tup[1]

            current_path = StoreTree.concat_paths([old_path, current_folder['name']])

            for item_def in current_folder['files'] + current_folder['folders']:
                res = {
                    'id': item_def['id'],
                    'name': item_def['name'],
                    'parent_path': current_path,
                    'is_folder': StoreTree.item_is_folder(item_def)}

                if StoreTree.item_is_folder(item_def):
                    stack.append((item_def, current_path))
                else:
                    res['modified'] = item_def['modified']

                yield res
