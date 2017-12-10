from setuptools import setup

__version__ = '0.0.11'

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
