#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Created: 2016-08-10

@author: pymancer

windows executable cx_Freeze builder config

usage:
python setup.py build
"""

from setuptools import setup

from cmr import __version__

requires = [
    'requests',
    'requests_toolbelt'
]

setup(
    name="mail.ru-cli",
    version=__version__,
    description="unofficial mail.ru command line tool",
    packages=['cmr'],
    package_data={'': ['LICENSE']},
    package_dir={'cmr': 'cmr'},
    entry_points={
        'console_scripts': ['cmr=cmr:shell'],
    },
    install_requires=requires,
    license='MIT',
)
