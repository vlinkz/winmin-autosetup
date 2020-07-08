#!/usr/bin/python3
from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

setup(
    name='winmin-autosetup',
    version='0.0.1',
    description='winmin autosetup script',
    author='Victor Fuentes',
    author_email='hyruleterminatirforce@gmail.com',
    python_requires='>=3.5, <4',
    project_urls={
        'Source': 'https://github.com/vlinkz',
    },
    packages=['winmin-autosetup-scripts'],
    scripts=['winmin-autosetup-scripts/winmin_autosetup.py'],
    entry_points = {
        'console_scripts': [
            'winmin-autosetup = winmin_autosetup:main',             
        ],
    },
)
