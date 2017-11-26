import unittest
from cmr import upload, download, get_list


class TestCopy(unittest.TestCase):
    def test_upload(self):
        upload('./test/', '/RELEASE/test')

    def test_upload_file(self):
        upload('.gitignore', '/RELEASE/.git')

    def test_download(self):
        download('/RELEASE/changelog.txt', './11.txt')

    def test_listing(self):
        l = get_list('/RELEASE/')
        print(l)
