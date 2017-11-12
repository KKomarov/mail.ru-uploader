#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Created: 2016-08-09

@author: pymancer

uploads specified directory contents to mail.ru cloud
- same name files in the cloud will NOT be replaced (still zipped and posted though)
- preserves upload directory structure
- functions are not fully designed for import

requirements (Python 3.5):
pip install requests requests-toolbelt

example run from venv:
python -m upload
"""
import os
import re
import sys
import json
import time
import zlib
import logging
import os.path
import zipfile
import requests
import datetime
import configparser
import shutil

from shutil import move
from mimetypes import guess_type
from requests_toolbelt import MultipartEncoder
from requests.compat import urljoin, quote_plus
from logging.handlers import RotatingFileHandler

__version__ = '0.0.8'

IS_CONFIG_PRESENT = False  # local configuration file presence indicator
CONFIG_FILE = './.config'  # configuration file, will be created on the very first use
# trying to load local configuration file
config = configparser.ConfigParser(delimiters=(':'))
config.optionxform = str
if config.read(CONFIG_FILE):
    IS_CONFIG_PRESENT = True

# frozen executable check
IS_FROZEN = getattr(sys, 'frozen', False)

###----- GENERAL CONFIGURATION PARAMETERS-------###
# do not forget to accept https://cloud.mail.ru/LA/ before first use by entering the cloud with browser)
# please, use only forward slashes in path variables
# please, note, that the last three variables in this block are generally are OK without any changes
# full mail.ru email address
LOGIN = config.get('Credentials', 'Email', fallback='your_email@mail.ru')
# email password
PASSWORD = config.get('Credentials', 'Password', fallback='your_email_password')
# absolute cloud path (without 'home')
CLOUD_PATH = config.get('Locations', 'CloudPath', fallback='/backups')
# local folder path with files to upload, use '.' to set path relative to the module location
UPLOAD_PATH = config.get('Locations', 'UploadPath', fallback='./upload')
# local folder to move uploaded files, will be created if not exists
UPLOADED_PATH = config.get('Locations', 'UploadedPath', fallback='./uploaded')
# True, if False - no uploaded files zipping
ARCHIVE_FILES = config.getboolean('Behaviour', 'ArchiveFiles', fallback=True)
# True, if False - old files should be deleted manually before next session
REMOVE_UPLOADED = config.getboolean('Behaviour', 'RemoveUploaded', fallback=True)
# False, if True uploaded files will be moved to UPLOADED_PATH directory, REMOVE_UPLOADED setting will be ignored
MOVE_UPLOADED = config.getboolean('Behaviour', 'MoveUploaded', fallback=False)
# True, will delete empty upload folders, will leave root folder, if False only files will be removed or moved if set
REMOVE_FOLDERS = config.getboolean('Behaviour', 'RemoveFolders', fallback=True)
###--------------------------------------###

LOG_FILE = './upload.log'  # log file path relative to the module location
CLOUD_URL = 'https://cloud.mail.ru/api/v2/'
LOGIN_CHECK_STRING = '"storages"'  # simple way to check successful cloud authorization
VERIFY_SSL = True  # True, use False only for debug and if you know what you're doing
CLOUD_DOMAIN_ORD = 2  # 2 - practice, 1 - theory
API_VER = 2  # 2 - constant so far
TIME_AMEND = '0246'  # '0246', exact meaning has not been quite sorted out yet
CLOUD_CONFLICT = 'strict'  # 'strict' - should remain constant at least until 'rename' implementation
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2*1024*1024*1024 (bytes ~ 2 GB), API constraint
FILES_TO_PRESERVE = ('application/zip',)  # do not archive already zipped files
DEFAULT_FILETYPE = 'text/plain'  # 'text/plain' is good option
# do not upload this files (only for module's directory)
FILES_TO_SKIP = {os.path.basename(CONFIG_FILE), os.path.basename(LOG_FILE)}
CACERT_FILE = 'cacert.pem'
EMAIL_REGEXP = re.compile(r'^.+\@.+\..+$')


class CallsCounter():
    """ instantiate with a target callable to count calls """

    def __init__(self, callable):
        self.calls = 0
        self.callable = callable

    def __call__(self, *args, **kwargs):
        self.calls += 1
        return self.callable(*args, **kwargs)


def get_logger(name, log_file=LOG_FILE):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    # create a file handler
    handler = RotatingFileHandler(log_file, mode='a', maxBytes=5 * 1024 * 1024, backupCount=2, encoding=None, delay=0)
    handler.setLevel(logging.INFO)
    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(handler)
    # enable statistics
    logger.error = CallsCounter(logger.error)
    logger.warning = CallsCounter(logger.warning)
    return logger
# setting up global logger
LOGGER = get_logger(__name__, log_file=LOG_FILE)


def get_email_domain(email=LOGIN):
    assert EMAIL_REGEXP.match(email), 'bad email provided: {}'.format(email)
    return email.split('@')[1]


def cloud_auth(session, login=LOGIN, password=PASSWORD):
    try:
        r = session.post('https://auth.mail.ru/cgi-bin/auth?lang=ru_RU&from=authpopup',
                         data={'Login': login, 'Password': password, 'page': urljoin(CLOUD_URL, '?from=promo'),
                               'new_auth_form': 1, 'Domain': get_email_domain(login)}, verify=VERIFY_SSL)
    except Exception as e:
        if LOGGER:
            LOGGER.error('Cloud auth HTTP request error: {}'.format(e))
        return None

    if r.status_code == requests.codes.ok:
        if LOGIN_CHECK_STRING in r.text:
            return True
        elif LOGGER:
            LOGGER.error('Cloud authorization request error. Check your credentials settings in {}. \
Do not forget to accept cloud LA by entering it in browser. \
HTTP code: {}, msg: {}'.format(CONFIG_FILE, r.status_code, r.text))
    elif LOGGER:
        LOGGER.error('Cloud authorization request error. Check your connection. \
HTTP code: {}, msg: {}'.format(r.status_code, r.text))
    return None


def get_csrf(session):
    try:
        r = session.get(urljoin(CLOUD_URL, 'tokens/csrf'), verify=VERIFY_SSL)
    except Exception as e:
        if LOGGER:
            LOGGER.error('Get csrf HTTP request error: {}'.format(e))
        return None

    if r.status_code == requests.codes.ok:
        r_json = r.json()
        token = r_json['body']['token']
        assert len(token) == 32, 'invalid CSRF token <{}> lentgh'.format(token)
        return token
    elif LOGGER:
        LOGGER.error('CSRF token request error. Check your connection and credentials settings in {}. \
HTTP code: {}, msg: {}'.format(CONFIG_FILE, r.status_code, r.text))
    return None


def get_upload_domain(session, csrf=''):
    """ return current cloud's upload domain url
    it seems that csrf isn't necessary in session,
    but forcing assert anyway to avoid possible future damage
    """
    assert csrf is not None, 'no CSRF'
    url = urljoin(CLOUD_URL, 'dispatcher?token=' + csrf)

    try:
        r = session.get(url, verify=VERIFY_SSL)
    except Exception as e:
        if LOGGER:
            LOGGER.error('Get upload domain HTTP request error: {}'.format(e))
        return None

    if r.status_code == requests.codes.ok:
        r_json = r.json()
        return r_json['body']['upload'][0]['url']
    elif LOGGER:
        LOGGER.error('Upload domain request error. Check your connection. \
HTTP code: {}, msg: {}'.format(r.status_code, r.text))
    return None


def get_cloud_csrf(session):
    if cloud_auth(session):
        return get_csrf(session)
    return None



def make_post(session, obj='', csrf='', command='', params=None):
    """ invokes standart cloud post operation
    tested operations: ('file/add', 'folder/add', 'file/remove')
    does not replace existent objects, but logs them
    """
    assert obj is not None, 'no object'
    assert csrf is not None, 'no CSRF'
    assert command is not None, 'no command'

    url = urljoin(CLOUD_URL, command)
    # api (implemented), email, x-email, x-page-id, build - optional parameters
    postdata = {'home': obj, 'conflict': CLOUD_CONFLICT, 'token': csrf, 'api': API_VER}
    if params:
        assert isinstance(params, dict), 'additional parameters not in dictionary'
        postdata.update(params)

    try:
        r = session.post(url, data=postdata, headers={'Content-Type': 'application/x-www-form-urlencoded'},
                         verify=VERIFY_SSL)
    except Exception as e:
        if LOGGER:
            LOGGER.error('Make post ({}) HTTP request error: {}'.format(command, e))
        return None

    if r.status_code == requests.codes.ok:
        return True
    elif r.status_code == requests.codes.bad:
        try:
            r_error = r.json()['body']['home']['error']
        except KeyError:
            r_error = None
        if r_error == 'exists':
            if LOGGER:
                LOGGER.warning('Command {} failed. Object {} already exists'.format(command, obj))
            return True
    if LOGGER:
        LOGGER.error(
            'Command {} on object {} failed. HTTP code: {}, msg: {}'.format(command, obj, r.status_code, r.text))
    return None




def zip_file(file):
    """ creates compressed zip files with same name and 'zip' extension
    on success removes original file
    on failure returns original file
    replaces existing archives
    param: file - filename with path (string)
    """
    file_path, file_name = os.path.split(file)
    zip_name = file_name + '.zip'
    compression = zipfile.ZIP_DEFLATED
    try:
        zf = zipfile.ZipFile(os.path.join(file_path, zip_name), mode='w')
        zf.debug = 0
        # convert unicode file names to byte strings if any
        zf.write(file, arcname=file_name, compress_type=compression)
    except Exception as e:
        zip_name = file_name
        if LOGGER:
            LOGGER.error('Failed to archive {}, error: {}'.format(file, e))
    else:
        os.unlink(file)
        if LOGGER:
            LOGGER.info('{} archived as {}'.format(file, os.path.join(file_path, zip_name)))
            LOGGER.info('file {} deleted after archiving'.format(file))
    finally:
        zf.close()
    return os.path.join(file_path, zip_name)


def get_dir_files(path=UPLOAD_PATH, space=0):
    """ returns list of the cwd files, follows cloud restrictions """
    assert space is not None, 'No cloud space left or space fetching error'

    for filename in next(os.walk(path))[2]:
        file = os.path.join(path, filename)
        # in case we uploading current directory
        if filename in FILES_TO_SKIP and path == '.':
            continue
        # in case some files are already zipped
        if ARCHIVE_FILES and guess_type(file)[0] not in FILES_TO_PRESERVE:
            file = zip_file(file)
        # api restriction
        file_size = os.path.getsize(file)
        if file_size < MAX_FILE_SIZE:
            if file_size < space:
                yield file
            else:
                if LOGGER:
                    LOGGER.warning(
                        'Not enough cloud space for <{}>. Left: {} (B). Required: {} (B).'.format(file, space,
                                                                                                  file_size))
                continue
        else:
            if LOGGER:
                LOGGER.warning('File {} is too large, omitting'.format(file))
            continue


def get_yes_no(value):
    """ coercing boolean value to 'yes' or 'no' """
    return 'yes' if value else 'no'


def create_cloud_path(path, cloud_base=CLOUD_PATH, local_base=UPLOAD_PATH):
    """ converts os path to the format acceptable by the cloud
    example:
    >>> cloud_base='/backups'
    >>> local_base='./upload'
    >>> path='./upload\\level1_1'
    >>> create_cloud_path(path, cloud_base, local_base)
    '/backups/level1_1'
    """
    normalized_path = path.replace('\\', '/')
    clean_path = normalized_path.replace(local_base, '', 1)
    return cloud_base + clean_path


def resource_path(relative_path):
    """ Get absolute path to resource (source or frozen) """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)

    return os.path.join(os.path.abspath('.'), relative_path)


def close_logger(logger):
    handlers = logger.handlers[:]
    for handler in handlers:
        handler.close()
        logger.removeHandler(handler)


class CloudMailRu(requests.Session):
    def __init__(self, *args, **kwargs):
        self.cloud_api = 'https://cloud.mail.ru/api/v2/'
        self.cloud_csrf = None
        self.upload_domain = None
        self.download_domain = None
        super(CloudMailRu, self).__init__()

    def __enter__(self):
        session = super(CloudMailRu, self).__enter__()
        self.cloud_csrf = get_cloud_csrf(session)
        self.upload_domain, self.download_domain = self.get_domains()

        return self

    def get_domains(self):
        url = urljoin(self.cloud_api, 'dispatcher?token=' + self.cloud_csrf)
        r = self.get(url, verify=VERIFY_SSL)

        if r.status_code == requests.codes.ok:
            r_json = r.json()
            return r_json['body']['upload'][0]['url'], r_json['body']['get'][0]['url']

    def add_file(self, file, hash='', size=0):
        """ 'file' should be filename with absolute cloud path """
        assert len(hash) == 40, 'invalid hash: {}'.format(hash)
        assert size >= 0, 'invalid size: {}'.format(size)

        return make_post(self, obj=file, csrf=self.cloud_csrf, command='file/add', params={'hash': hash, 'size': size})

    def create_folder(self, folder=''):
        """ Takes 'folder' as new folder name with full cloud path (without 'home'),
        returns True even if target folder already existed
        Path should start with forward slash,
        no final slash should be present after the target folder name
        """
        return make_post(self, obj=folder, csrf=self.cloud_csrf, command='folder/add')

    def remove_object(self, obj=''):
        """ moves a file or a folder to the cloud's recycle bin
        at his time utilized in testing only
        example call: remove_object(session, obj='/backups/test.txt', csrf='8q3q6wUF3HLVZReni3SGna5vHsbgtDEx')
        """
        return make_post(self, obj=obj, csrf=self.cloud_csrf, command='file/remove')

    def get_file(self, file_path, dest_path):
        # url = urljoin(self.download_domain, file_path)
        url = self.download_domain + file_path
        try:
            r = self.get(url, stream=True, verify=VERIFY_SSL)
            print(r)
            if r.status_code != 200:
                return
            with open(dest_path, 'wb') as f:
                r.raw.decode_content = True
                shutil.copyfileobj(r.raw, f)

        except:
            pass

    def list_files(self, dir):
        url = self.cloud_api + 'folder?home={dir}&token={token}'.format(dir=dir, token=self.cloud_csrf)
        r = self.get(url, verify=VERIFY_SSL)
        if r.status_code != 200:
            return
        print(r.text)

    def post_file(self, file, login=LOGIN):
        """ posts file to the cloud's upload server
        param: file - string filename with path
        """
        assert file is not None, 'no file'

        filetype = guess_type(file)[0]
        if not filetype:
            filetype = DEFAULT_FILETYPE
            if LOGGER:
                LOGGER.warning('File {} type is unknown, using default: {}'.format(file, DEFAULT_FILETYPE))

        filename = os.path.basename(file)
        quoted_login = quote_plus(login)
        timestamp = str(int(time.mktime(datetime.datetime.now().timetuple()))) + TIME_AMEND
        url = urljoin(self.upload_domain,
                      '?cloud_domain=' + str(CLOUD_DOMAIN_ORD) + '&x-email=' + quoted_login + '&fileapi' + timestamp)
        with open(file, 'rb') as f:
            m = MultipartEncoder(fields={'file': (quote_plus(filename), f, filetype)})

            try:
                r = self.post(url, data=m, headers={'Content-Type': m.content_type}, verify=VERIFY_SSL)
            except Exception as e:
                if LOGGER:
                    LOGGER.error('Post file HTTP request error: {}'.format(e))
                return None, None

        if r.status_code == requests.codes.ok:
            if len(r.content):
                hash = r.content[:40].decode()
                size = int(r.content[41:-2])
                return hash, size
            elif LOGGER:
                LOGGER.error('File {} post error, no hash and size received'.format(file))
        elif LOGGER:
            LOGGER.error('File {} post error, http code: {}, msg: {}'.format(file, r.status_code, r.text))
        return None, None

    def upload_file(self, local_path, cloud_path):
        pass

    def get_cloud_space(self, login=LOGIN):
        """ returns available free space in bytes """

        timestamp = str(int(time.mktime(datetime.datetime.now().timetuple()) * 1000))
        quoted_login = quote_plus(login)
        command = ('user/space?api=' + str(API_VER) + '&email=' + quoted_login +
                   '&x-email=' + quoted_login + '&token=' + self.cloud_csrf + '&_=' + timestamp)
        url = urljoin(CLOUD_URL, command)

        try:
            r = self.get(url, verify=VERIFY_SSL)
        except Exception as e:
            if LOGGER:
                LOGGER.error('Get cloud space HTTP request error: {}'.format(e))
            return 0

        if r.status_code == requests.codes.ok:
            r_json = r.json()
            total_bytes = r_json['body']['total'] * 1024 * 1024
            used_bytes = r_json['body']['used'] * 1024 * 1024
            return total_bytes - used_bytes
        elif LOGGER:
            LOGGER.error('Cloud free space request error. Check your connection. \
    HTTP code: {}, msg: {}'.format(r.status_code, r.text))
        return 0


def shell():
    import argparse
    parser = argparse.ArgumentParser(description='Copies a local file or cloud object to '
                                                 'another location locally or to cloud.')
    group1 = parser.add_argument_group('group1', 'group1 description')

    group1.add_argument('op', choices=['cp', 'mv', 'rm'], help='operation')
    group2 = parser.add_argument_group('group2', 'group2 description')

    group2.add_argument('from_path')
    group2.add_argument('to_path')
    group2.add_argument('--recursive', '-r', action='store_true')

    args = parser.parse_args()
    print(args)
    if args.op == 'cp':
       copy_dir(args.from_path, args.to_path)


def copy_dir(from_path, to_path):
    cert_stuff()
    os.path.isdir(from_path)
    uploaded_files = set()
    with CloudMailRu() as api:
        for folder, __, __ in list(os.walk(from_path)):
            # cloud dir should exist before uploading
            cloud_path = create_cloud_path(folder, cloud_base=to_path, local_base=from_path)
            api.create_folder(folder=cloud_path)
            # uploading files
            try:
                for file in get_dir_files(path=folder, space=api.get_cloud_space()):
                    hash, size = api.post_file(file=file)
                    if size >= 0 and hash:
                        LOGGER.info('File {} successfully posted'.format(file))
                        cloud_file = cloud_path + '/' + os.path.basename(file)
                        if api.add_file(file=cloud_file, hash=hash, size=size):
                            LOGGER.info('File {} successfully added'.format(file))
                            uploaded_files.add(file)
            except:
                LOGGER.error('File upload error:', exc_info=True)
                raise
    print(uploaded_files)
    uploaded_num = len(uploaded_files)


def copy_file(from_path, to_path):
    cert_stuff()
    downloaded = set()
    with CloudMailRu() as api:
        api.get_file(from_path, to_path)
    print(downloaded)
    uploaded_num = len(downloaded)


def get_list(cloud_path):
    cert_stuff()
    with CloudMailRu() as api:
        return api.list_files(cloud_path)


def cert_stuff():
    if IS_FROZEN:
        # do not upload self, skip exe file with dependencies
        FILES_TO_SKIP.add(os.path.basename(sys.executable))
        # supplying ca certificate for https
        # cacert file should be in module's directory
        # for cx_Freeze
        # cacert = os.path.join(os.path.dirname(sys.executable), CACERT_FILE)
        # for PyInstaller
        cacert = resource_path(CACERT_FILE)
    else:
        # provide CA cert (not necessary)
        cacert = requests.certs.where()
        # do not upload self, skip module's file
        try:
            self_file = os.path.basename(os.path.abspath(sys.modules['__main__'].__file__))
        except:
            LOGGER.warning('Cannot get self file name.')
        else:
            FILES_TO_SKIP.add(self_file)
    assert os.path.isfile(cacert), 'Fatal Error. CA certificate not found.'
    os.environ["REQUESTS_CA_BUNDLE"] = cacert


if __name__ == '__main__':
    shell()
