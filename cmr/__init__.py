#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Created: 2016-08-09

@author: pymancer, KKomarov

uploads specified directory contents to mail.ru cloud
- same name files in the cloud will NOT be replaced (still zipped and posted though)
- preserves upload directory structure
- functions are not fully designed for import

requirements (Python 3.5):
pip install requests requests-toolbelt

example run from venv:
python -m upload
"""
import argparse
import configparser
import datetime
import logging
import os
import os.path
import re
import shutil
import sys
import time
from logging.handlers import RotatingFileHandler
from mimetypes import guess_type

import requests
from requests.compat import urljoin, quote_plus
from requests_toolbelt import MultipartEncoder

__all__ = ['shell', 'CloudMailRu', 'upload', 'download', 'get_list']

__version__ = '0.0.9'

IS_CONFIG_PRESENT = False  # local configuration file presence indicator
CONFIG_FILE = os.path.expanduser('~/.cmr')  # configuration file, will be created on the very first use
# trying to load local configuration file
config = configparser.ConfigParser(delimiters=':')
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
LOGIN = config.get('Credentials', 'cmr_email', fallback='your_email@mail.ru')
# email password
PASSWORD = config.get('Credentials', 'cmr_pwd', fallback='your_email_password')

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


def get_yes_no(value):
    """ coercing boolean value to 'yes' or 'no' """
    return 'yes' if value else 'no'


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
        print('%s -> %s' % (file_path, dest_path))
        url = self.download_domain + file_path
        try:
            r = self.get(url, stream=True, verify=VERIFY_SSL)
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
            return []
        return r.json()['body']['list']

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

    def upload_file(self, local_file, cloud_file):
        hash, size = self.post_file(file=local_file)
        if size >= 0 and hash:
            LOGGER.info('File {} successfully posted'.format(local_file))
            if self.add_file(file=cloud_file, hash=hash, size=size):
                LOGGER.info('File {} successfully added'.format(local_file))

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


def shell(args_list=None):
    parser = argparse.ArgumentParser(description='File operations with mail ru cloud.')
    parser.add_argument('op', choices=['cp', 'configure'], help='operation')  # 'mv', 'rm',
    parser.add_argument('rest', nargs=argparse.REMAINDER)

    args = parser.parse_args(args_list)
    print(args)
    if args.op == 'configure':
        configure_shell(args.rest)
    if args.op == 'cp':
        copy_shell(args.rest)


def configure_shell(args=None):
    '''
    >>> configure_shell([])

    '''
    parser = argparse.ArgumentParser(description='Configure cloud mail ru client.')
    parser.parse_args(args)
    section = 'Credentials'
    if not config.has_section(section):
        config.add_section(section)
    values_to_promt = [
        ('cmr_email', 'Email'),
        ('cmr_pwd', 'Password'),
    ]
    for config_name, prompt_text in values_to_promt:
        current_value = config.get(section, config_name, fallback='')
        new_value = get_value(current_value, config_name, prompt_text)
        if new_value is not None and new_value != current_value:
            config.set(section, config_name, new_value)
    with open(CONFIG_FILE, mode='w') as f:
        config.write(f)


def copy_shell(args_list=None):
    parser = argparse.ArgumentParser(description='Copies a local file or cloud object to '
                                                 'another location locally or to cloud.',
                                     usage='%(prog)s cp [-h] [-r] from_path to_path')
    parser.add_argument('from_path')
    parser.add_argument('to_path')
    parser.add_argument('-r', '--recursive', action='store_true')
    args = parser.parse_args(args_list)

    cloud_prefix = 'cmr:/'
    if args.from_path.startswith(cloud_prefix):
        from_path = args.from_path[len(cloud_prefix):]
        download(from_path, args.to_path, args.recursive)
    elif args.to_path.startswith(cloud_prefix):
        to_path = args.to_path[len(cloud_prefix):]
        upload(args.from_path, to_path, args.recursive)
    else:
        print("Can't copy local files")


def get_value(current_value, config_name, prompt_text=''):
    if config_name in ('cmr_pwd',):
        current_value = mask_value(current_value)
    response = get_input("%s [%s]: " % (prompt_text, current_value))
    if not response:
        response = None
    return response


def mask_value(current_value):
    if current_value is None:
        return 'None'
    else:
        return ('*' * 16) + current_value[-4:]


def get_input(prompt):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return input()


def upload(from_path, to_path, recursive=False):
    cert_stuff()
    uploaded_files = set()
    if not os.path.exists(from_path):
        print('%s not exists' % from_path)
        return
    single_file = os.path.isfile(from_path)
    if single_file:
        to_load = [(os.path.normpath(os.path.dirname(from_path)), '', (os.path.basename(from_path),))]
        cloud_base_dir = os.path.dirname(to_path)
        local_base_dir = os.path.dirname(from_path)
    else:
        to_load = os.walk(from_path)
        cloud_base_dir = to_path
        local_base_dir = from_path
    with CloudMailRu() as api:
        for folder, __, file_names in to_load:
            # cloud dir should exist before uploading
            cloud_dir = create_cloud_path(folder, cloud_base=cloud_base_dir, local_base=local_base_dir)
            api.create_folder(folder=cloud_dir)
            for local_file in file_names:
                local_path = os.path.join(folder, local_file)
                cloud_file = cloud_dir + '/' + local_file
                if single_file and not to_path.endswith('/'):
                    cloud_file = to_path
                try:
                    api.upload_file(local_path, cloud_file)
                except:
                    LOGGER.error('File upload error:', exc_info=True)
                print('%s -> %s' % (local_path, cloud_file))
                uploaded_files.add(local_path)
            if not recursive:
                break
    print('Uploaded %s files' % len(uploaded_files))


def make_cloud_path(*dirs, cloud_base, local_base):
    '''
    join dirs, normalize and return absolute path to cloud
    >>> make_cloud_path('/', '.\\.git', )
    '/.git'
    >>> make_cloud_path('/base', '.\\.git\\info', 'exclude')
    '/base/.git/info/exclude'
    >>> make_cloud_path('/base', '.\\.git\\info\')
    '/base/.git/info'

    '''
    path = os.path.join(*dirs)
    return os.path.normpath(path).replace('\\', '/')


def create_cloud_path(path, cloud_base, local_base):
    """ converts os path to the format acceptable by the cloud
    example:
    >>> cloud_base='/backups'
    >>> local_base='./upload'
    >>> path='./upload\\level1_1'
    >>> create_cloud_path(path, cloud_base, local_base)
    '/backups/level1_1'
    >>> create_cloud_path('/file1', '')
    """
    normalized_path = path.replace('\\', '/')
    clean_path = normalized_path.replace(local_base, '', 1)
    result = cloud_base + clean_path
    return os.path.normpath(result).replace('\\', '/')


def download(from_path, to_path, recursive=False):
    cert_stuff()
    downloaded = set()
    with CloudMailRu() as api:
        list_of_objects = api.list_files(from_path)
        cloud_is_dir = any(o['type'] == 'folder' and o['home'] == from_path for o in list_of_objects)
        is_dir = os.path.isdir(to_path)
        if not cloud_is_dir:
            if is_dir:
                to_path = os.path.join(to_path, os.path.basename(from_path))
            api.get_file(from_path, to_path)
            downloaded.add(from_path)
            print('Downloaded: %s' % len(downloaded))
            return

        if not is_dir:
            print("Can't dir to file")
            return

        for o in list_of_objects:
            obj_type, obj_home = o['type'], o['home']
            if obj_type != 'file':
                continue
            cloud_name = os.path.basename(obj_home)
            local_file = to_path
            if is_dir:
                local_file = os.path.join(to_path, cloud_name)

            api.get_file(obj_home, local_file)
            downloaded.add(obj_home)

    print('Downloaded: %s' % len(downloaded))


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
