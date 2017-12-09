import unittest
from unittest.mock import patch, call

from cmr import shell
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

    def test_ls(self):
        shell(['ls'])

    @patch('cmr.CloudMailRu')
    def test_shell_cp1(self, api_mock):
        shell(['cp', 'upload.log', 'cmr://.gitignore'])
        print(api_mock.mock_calls)
        api_mock.assert_has_calls([call().__enter__().upload_file('.\\upload.log', '/.gitignore')])

    @patch('cmr.CloudMailRu')
    def test_shell_cp2(self, api_mock):
        shell(['cp', 'dir1', 'cmr://tdir1'])
        print(api_mock.mock_calls)
        # no uploaded
        api_mock.assert_has_calls([])

    @patch('cmr.CloudMailRu')
    def test_shell_cp3(self, api_mock):
        shell(['cp', '-r', 'dir1', 'cmr://tdir1'])
        print(api_mock.mock_calls)
        api_mock.assert_has_calls([call().__enter__().upload_file('dir1\\dir2\\11.txt', '/tdir1/dir2/11.txt')])

    @patch('cmr.CloudMailRu')
    def test_shell_cp4(self, api_mock):
        shell(['cp', 'dir1/dir2/11.txt', 'cmr://tdir2/'])
        print(api_mock.mock_calls)
        api_mock.assert_has_calls([call().__enter__().upload_file('dir1\\dir2\\11.txt', '/tdir2/11.txt')])

    @patch('cmr.CloudMailRu')
    def test_shell_cp5(self, api_mock):
        shell(['cp', 'dir1/dir2/11.txt', 'cmr://cdir/renamed.txt'])
        print(api_mock.mock_calls)
        api_mock.assert_has_calls([call().__enter__().upload_file('dir1\\dir2\\11.txt', '/cdir/renamed.txt')])
