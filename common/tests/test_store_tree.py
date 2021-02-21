import unittest
from common.tree_utils import StoreTree


class TestStoreTree(unittest.TestCase):

    def testGetfilePathsList(self):
        tree = StoreTree(0)

        tree.add_folder(1, 'folder1')
        tree.add_folder(2, 'folder2')
        tree.add_folder(3, 'folder3')
        tree.add_folder(4, 'folder4', parent_id=1)
        tree.add_folder(5, 'folder5', parent_id=3)

        tree.add_file(6, 'file1.txt')
        tree.add_file(7, 'file2', parent_id=4)
        tree.add_file(8, 'file3.png')

        file_paths = tree.get_file_paths_list()

        self.assertEqual(len(file_paths), 3)
        self.assertIn(StoreTree.concat_paths(['', 'file1.txt']), file_paths)
        self.assertIn(StoreTree.concat_paths(['', 'folder1', 'folder4', 'file2']), file_paths)
        self.assertIn(StoreTree.concat_paths(['', 'file3.png']), file_paths)

    def testFindItemById(self):
        tree = StoreTree(0)

        tree.add_folder(1, 'folder1')
        tree.add_folder(2, 'folder2')
        tree.add_folder(3, 'folder3')
        tree.add_folder(4, 'folder4', parent_id=1)
        tree.add_folder(5, 'folder5', parent_id=3)

        tree.add_file(6, 'file1.txt')
        tree.add_file(7, 'file2', parent_id=4)
        tree.add_file(8, 'file3.png')

        root_dict = tree.find_item_by_id(0)
        self.assertEqual(len(root_dict['files']), 2)
        self.assertEqual(len(root_dict['folders']), 3)
        self.assertEqual(root_dict['id'], 0)
        self.assertEqual(root_dict['name'], '')

        folder1_dict = tree.find_item_by_id(1)
        self.assertEqual(len(folder1_dict['files']), 0)
        self.assertEqual(len(folder1_dict['folders']), 1)
        self.assertEqual(folder1_dict['id'], 1)
        self.assertEqual(folder1_dict['name'], 'folder1')

        folder4_dict = tree.find_item_by_id(4)
        self.assertEqual(len(folder4_dict['files']), 1)
        self.assertEqual(len(folder4_dict['folders']), 0)
        self.assertEqual(folder4_dict['id'], 4)
        self.assertEqual(folder4_dict['name'], 'folder4')

        file1_dict = tree.find_item_by_id(6)
        self.assertEqual(file1_dict['id'], 6)
        self.assertEqual(file1_dict['name'], 'file1.txt')

        file2_dict = tree.find_item_by_id(7)
        self.assertEqual(file2_dict['id'], 7)
        self.assertEqual(file2_dict['name'], 'file2')

        file3_dict = tree.find_item_by_id(8)
        self.assertEqual(file3_dict['id'], 8)
        self.assertEqual(file3_dict['name'], 'file3.png')

        self.assertIs(tree.find_item_by_id(39), None)

        # ================================================
        # Test find parent

        folder3_dict, _ = tree.find_item_parent_by_id(5)
        self.assertEqual(len(folder3_dict['files']), 0)
        self.assertEqual(len(folder3_dict['folders']), 1)
        self.assertEqual(folder3_dict['id'], 3)
        self.assertEqual(folder3_dict['name'], 'folder3')

        root_dict, _ = tree.find_item_parent_by_id(2)
        self.assertEqual(len(root_dict['files']), 2)
        self.assertEqual(len(root_dict['folders']), 3)
        self.assertEqual(root_dict['id'], 0)
        self.assertEqual(root_dict['name'], '')

        self.assertIs(tree.find_item_parent_by_id(29)[0], None)

    def testFindItemByPath(self):
        tree = StoreTree(0)

        tree.add_folder(1, 'folder1')
        tree.add_folder(2, 'folder2')
        tree.add_folder(3, 'folder3')
        tree.add_folder(4, 'folder4', parent_id=1)
        tree.add_folder(5, 'folder5', parent_id=3)

        tree.add_file(6, 'file1.txt')
        tree.add_file(7, 'file2', parent_id=4)
        tree.add_file(8, 'file3.png')

        root_dict = tree.find_item_by_path('')
        self.assertEqual(len(root_dict['files']), 2)
        self.assertEqual(len(root_dict['folders']), 3)
        self.assertEqual(root_dict['id'], 0)
        self.assertEqual(root_dict['name'], '')

        folder1_dict = tree.find_item_by_path('folder1/', is_path_to_file=False)
        self.assertEqual(len(folder1_dict['files']), 0)
        self.assertEqual(len(folder1_dict['folders']), 1)
        self.assertEqual(folder1_dict['id'], 1)
        self.assertEqual(folder1_dict['name'], 'folder1')

        folder3_dict = tree.find_item_by_path('folder3', is_path_to_file=False)
        self.assertEqual(len(folder3_dict['files']), 0)
        self.assertEqual(len(folder3_dict['folders']), 1)
        self.assertEqual(folder3_dict['id'], 3)
        self.assertEqual(folder3_dict['name'], 'folder3')

        folder4_dict = tree.find_item_by_path('folder1/folder4', is_path_to_file=False)
        self.assertEqual(len(folder4_dict['files']), 1)
        self.assertEqual(len(folder4_dict['folders']), 0)
        self.assertEqual(folder4_dict['id'], 4)
        self.assertEqual(folder4_dict['name'], 'folder4')

        file1_dict = tree.find_item_by_path('file1.txt', is_path_to_file=True)
        self.assertEqual(file1_dict['id'], 6)
        self.assertEqual(file1_dict['name'], 'file1.txt')

        file1_dict = tree.find_item_by_path('file1.txt', is_path_to_file=True)
        self.assertEqual(file1_dict['id'], 6)
        self.assertEqual(file1_dict['name'], 'file1.txt')

        file2_dict = tree.find_item_by_path('folder1/folder4/file2', is_path_to_file=True)
        self.assertEqual(file2_dict['id'], 7)
        self.assertEqual(file2_dict['name'], 'file2')

        file3_dict = tree.find_item_by_path('file3.png', is_path_to_file=True)
        self.assertEqual(file3_dict['id'], 8)
        self.assertEqual(file3_dict['name'], 'file3.png')

        self.assertIs(tree.find_item_by_path('folder4'), None)
        self.assertIs(tree.find_item_by_path('folder1/folder4/file3', is_path_to_file=True), None)
        self.assertIs(tree.find_item_by_path('folder1/folder4/file3', is_path_to_file=False), None)
        self.assertIs(tree.find_item_by_path('folder1/folder4', is_path_to_file=True), None)



    def testMoveItem(self):
        tree = StoreTree(0)

        tree.add_folder(1, 'folder1')
        tree.add_folder(2, 'folder2')
        tree.add_folder(3, 'folder3')
        tree.add_folder(4, 'folder4', parent_id=1)
        tree.add_folder(5, 'folder5', parent_id=3)

        tree.add_file(6, 'file1.txt')
        tree.add_file(7, 'file2', parent_id=4)
        tree.add_file(8, 'file3.png')

        tree.move_item(4, 0)

        root_dict = tree.find_item_by_id(0)
        self.assertEqual(len(root_dict['files']), 2)
        self.assertEqual(len(root_dict['folders']), 4)
        self.assertEqual(root_dict['id'], 0)
        self.assertEqual(root_dict['name'], '')

        folder1_dict = tree.find_item_by_id(1)
        self.assertEqual(len(folder1_dict['files']), 0)
        self.assertEqual(len(folder1_dict['folders']), 0)
        self.assertEqual(folder1_dict['id'], 1)
        self.assertEqual(folder1_dict['name'], 'folder1')

        folder4_dict = tree.find_item_by_id(4)
        self.assertEqual(len(folder4_dict['files']), 1)
        self.assertEqual(len(folder4_dict['folders']), 0)
        self.assertEqual(folder4_dict['id'], 4)
        self.assertEqual(folder4_dict['name'], 'folder4')

        file_paths = tree.get_file_paths_list()
        self.assertEqual(len(file_paths), 3)
        self.assertIn(StoreTree.concat_paths(['', 'file1.txt']), file_paths)
        self.assertIn(StoreTree.concat_paths(['', 'folder4', 'file2']), file_paths)
        self.assertIn(StoreTree.concat_paths(['', 'file3.png']), file_paths)

    def testCreateFromId(self):
        tree = StoreTree(0)

        # - folder1 - folder4 - file2
        #           - file4
        # - folder2
        # - folder3 - folder5
        # - file1.txt
        # - file3.png

        tree.add_folder(1, 'folder1')
        tree.add_folder(2, 'folder2')
        tree.add_folder(3, 'folder3')
        tree.add_folder(4, 'folder4', parent_id=1)
        tree.add_folder(5, 'folder5', parent_id=3)

        tree.add_file(6, 'file1.txt')
        tree.add_file(7, 'file2', parent_id=4)
        tree.add_file(8, 'file3.png')
        tree.add_file(9, 'file4', parent_id=1)

        new_tree = tree.create_new_from_id(1)

        # folder 1 is now the new root

        # - folder4 - file2
        # - file4

        root_dict = tree.find_item_by_id(1)
        self.assertEqual(len(root_dict['files']), 1)
        self.assertEqual(len(root_dict['folders']), 1)
        self.assertEqual(root_dict['id'], 1)
        self.assertEqual(root_dict['name'], 'folder1')

        file4_dict = root_dict['files'][0]
        self.assertEqual(file4_dict['id'], 9)
        self.assertEqual(file4_dict['name'], 'file4')

        folder4_dict = tree.find_item_by_id(4)
        self.assertEqual(len(folder4_dict['files']), 1)
        self.assertEqual(len(folder4_dict['folders']), 0)
        self.assertEqual(folder4_dict['id'], 4)
        self.assertEqual(folder4_dict['name'], 'folder4')

