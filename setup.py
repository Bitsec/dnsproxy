# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='dnsproxy',
    version='0.0.1',
    description='Python DNS Proxy Framework',
    long_description=readme,
    author='Bitsec AB',
    author_email='info@bitsec.se',
    url='https://github.com/bitsec/dnsproxy',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)
