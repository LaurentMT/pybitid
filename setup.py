#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='pybitid',
    packages=find_packages(exclude=['tests']),
    version='0.0.4',
    description='Python BitId Library',
    author='laurentmt',
    author_email='llll@lll.com',
    maintainer='laurentmt',
    url='https://www.github.com/LaurentMT/pybitid',
    download_url='https://www.github.com/LaurentMT/pybitid/tarball/0.0.4',
    keywords=['authentication', 'bitcoin', 'privacy'],
    classifiers=['Development Status :: 3 - Alpha', 'Intended Audience :: Developers', 'License :: OSI Approved :: MIT License',
                 'Natural Language :: English', 'Programming Language :: Python :: 2.7', 'Programming Language :: Python :: 3.3',
                 'Topic :: Security']
)
