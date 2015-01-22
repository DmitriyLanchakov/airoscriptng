#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')

requirements = [
    "netifaces",
    "futures",
    "psutil"
]

test_requirements = [
    "tox"
]

setup(
    name='airoscriptng',
    version='0.0.4',
    description='Airoscript-ng python complete implementation',
    long_description=readme + '\n\n' + history,
    author='David Francos Cuartero',
    author_email='me@davidfrancos.net',
    url='https://github.com/XayOn/airoscriptng',
    download_url='https://github.com/XayOn/airoscriptng/tarball/0.2',
    packages=[
        'airoscriptng',
    ],
    package_dir={'airoscriptng':
                 'airoscriptng'},
    include_package_data=True,
    install_requires=requirements,
    license="BSD",
    zip_safe=False,
    keywords='airoscriptng',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    entry_points={
        'console_scripts': [
            'airoscriptng = airoscriptng.airoscriptng:airoscriptxmlrpc',
        ],
    }
)
