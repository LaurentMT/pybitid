#!/usr/bin/env python
import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages

setup(
    name='pybitid',
    version='0.0.4',
    description='Python BitId Library',
    long_description=open('README.md').read(),
    author='laurentmt',
    maintainer='laurentmt',
    url='http://www.github.com/LaurentMT/pybitid',
    packages=find_packages(exclude=['tests']))
