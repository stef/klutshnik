#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name = 'klutshnik',
      version = '0.0.3',
      description = 'Klutshnik (and OPRF) CLI client',
      license = "GPLv3",
      author = 'Stefan Marsiske',
      author_email = 'klutshnik@ctrlc.hu',
      url = 'https://github.com/stef/klutshnik',
      long_description=read('README.org'),
      long_description_content_type="text/markdown",
      packages = ['klutshnik'],
      install_requires = ("pysodium", 'dissononce', 'opaquestore'),
      classifiers = ["Development Status :: 4 - Beta",
                     "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
                     "Topic :: Security :: Cryptography",
                     "Topic :: Security",
                     ],
      entry_points = {
          'console_scripts': [
              'klutshnik = klutshnik.client:main',
              'genkey25519 = klutshnik.genkey:main'
          ],
      },
)
