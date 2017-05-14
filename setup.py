from setuptools import setup
import os
import sys

import axeman

py_version = sys.version_info[:2]

if py_version < (3, 5):
    raise Exception("axeman requires Python >= 3.5.")

here = os.path.abspath(os.path.dirname(__file__))

with open('requirements.txt') as f:
    dependencies = f.read().splitlines()

long_description = """
Axeman uses co-routines and multiprocessing to download and process certificates from a Certificate Transparency
List and outputs them to CSV.
"""

setup(
    name='axeman',
    version=axeman.__version__,
    url='https://github.com/CaliDog/Axeman/',
    author='Ryan Sears',
    install_requires=dependencies,
    author_email='ryan@calidog.io',
    description='Lumberjack is a multi-threaded and concurrent certificate transparency retriever Edit',
    long_description=long_description,
    packages=['axeman'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'axeman = axeman.core:main',
        ],
    },
    license = "MIT",
    classifiers = [
        "License :: OSI Approved :: MIT License",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "Environment :: Console",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
)