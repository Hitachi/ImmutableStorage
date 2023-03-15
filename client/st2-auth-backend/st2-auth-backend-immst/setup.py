# -*- coding: utf-8 -*-
# Licensed to the StackStorm, Inc ('StackStorm') under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from setuptools import setup, find_packages

from dist_utils import check_pip_version
from dist_utils import fetch_requirements
from dist_utils import parse_version_string

check_pip_version()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS_FILE = os.path.join(BASE_DIR, 'requirements.txt')
INIT_FILE = os.path.join(BASE_DIR, 'st2auth_immst_backend', '__init__.py')

version = parse_version_string(INIT_FILE)
install_reqs, dep_links = fetch_requirements(REQUIREMENTS_FILE)

with open(os.path.join(BASE_DIR, "README.md"), "r") as fh:
    long_description = fh.read()

setup(
    name='st2-auth-backend-immst',
    version=version,
    description='StackStorm authentication backend which authenticates with Immutable Storage',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Eiichiro Oiwa',
    author_email='eiichiro.oiwa.nm@hitachi.com',
    url='https://github.com/Hitachi/ImmutableStorage',
    download_url='https://github.com/Hitachi/ImmutableStorage',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Intended Audience :: Developers',
        'Environment :: Console',
    ],
    platforms=['Any'],
    scripts=[],
    provides=['st2auth_immst_backend'],
    packages=['st2auth_immst_backend'],
    package_dir={'st2auth_immst_backend': 'st2auth_immst_backend'},
    include_package_data=True,
    install_requires=install_reqs,
    dependency_links=dep_links,
    test_suite='tests',
    entry_points={
        'st2auth.sso.backends': [
            'immst = st2auth_immst_backend.immst_auth:ImmStAuthenticationBackend',
        ],
    },
    zip_safe=False
)
