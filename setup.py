import os
from distutils.core import setup

NAME = 'py64'
VERSION = '0.0.1'

setup(
    name = 'pyc64',
    version = VERSION,
    author = 'Jesse Ward',
    author_email = 'jesse@jesseward.com',
    description = ('Commodore 64 emulator, written in Python'),
    license = 'MIT',
    url = 'https://github.com/jesseward/py64',
    scripts = ['scripts/py_64.py'],
    packages=['py64', 'py64/loaders'],
)
