#!/usr/bin/env python3
"""Setup script for lanagent package."""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='lanagent',
    version='0.1.0',
    author='Dr. Mickey Lauer',
    author_email='',  # Add your email when ready
    description='A network discovery service that scans local networks and exposes results via JSON API',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/lanagent',  # Update with your repo URL
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Networking',
        'Topic :: System :: Monitoring',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.7',
    install_requires=[
        'zeroconf>=0.38.0',
        'netifaces>=0.11.0',
    ],
    entry_points={
        'console_scripts': [
            'lanagent=lanagent.cli:main',
        ],
    },
    keywords='network discovery arp scanning zeroconf mdns json api',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/lanagent/issues',
        'Source': 'https://github.com/yourusername/lanagent',
    },
)