# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
setup(
    # basic package data
    name = "loginmgr",
    version = "0.1",
    description='Command line login manager, that holds a password encrypted storage of json encoded login entries.',
    long_description=README.md
    author='Belsebubben',
    url='https://github.com/belsebubben',
    license = "GPL v2",
    keywords = "login manager password encrypted safe",
    # package structure
    packages=find_packages('src'),
    package_dir={'':'src'},
    # install the rsreader executable
    entry_points = { 'loginmgr': [ 'loginmgr = loginmgr:main' ] },
    install_requires = [ 'cmd', ],

)

