import unittest
from upload import copy_dir, copy_file, get_list


class TestCopy(unittest.TestCase):
    def test_upload(self):
        copy_dir('./test/', '/RELEASE')

    def test_download(self):
        copy_file('/RELEASE/changelog.txt', './11.txt')

    def test_listing(self):
        get_list('/RELEASE/')
