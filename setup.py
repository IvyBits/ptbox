#!/usr/bin/env python
import ez_setup

ez_setup.use_setuptools()
from setuptools import setup, find_packages

with open('README.rst') as file:
    long_description = file.read()

setup(name='ptbox',
      version='0.1.0',
      description='ptrace sandbox for Unix systems',
      long_description=long_description,
      author='Tudor Brindus',
      author_email='tbrindus@gmail.com',
      url='http://github.com/IvyBits/ptbox',
      packages=find_packages(),
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: Software Development :: Debuggers',
          'Topic :: Security'
      ],
)