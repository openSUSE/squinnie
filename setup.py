#!/usr/bin/env python2

from __future__ import with_statement, print_function

from setuptools import setup
import os, sys
import glob

pkg_root = os.path.abspath(os.path.dirname(__file__))
readme_rst = os.path.join( pkg_root, "README.rst" )
remove_rst = False

def getLongDesc():
    global remove_rst

    if not os.path.exists(readme_rst):
        # dynamically generate a restructured text formatted long description
        # from markdown for setuptools to use
        import subprocess
        pandoc = "/usr/bin/pandoc"
        if not os.path.exists(pandoc):
            print("Can't generate RST readme from MD readme, because pandoc isn't installed. Skipping long description.", file = sys.stderr)
            return "no long description available"
        subprocess.check_call(
            [ pandoc, "-f", "markdown", "-t", "rst", "-o", "README.rst", "Readme.md" ],
            shell = False,
            close_fds = True
        )
        remove_rst = True

    with open(readme_rst, 'r') as rst_file:
        long_desc = rst_file.read()

    return long_desc

long_desc = getLongDesc()

try:

    setup(
        name = 'squinnie-security',
        version = '0.5.1',
        description = 'Squinnie is a security oriented system scanning utility for Linux',
        long_description = long_desc,
        author = 'Matthias Gerstner',
        author_email = 'matthias.gerstner@suse.com',
        license = 'GPL2',
        keywords = 'openSUSE security scanner review audit',
        packages = ['squinnie', 'squinnie.daw'],
        install_requires = ['execnet', 'terminaltables', 'termcolor'],
        url = 'https://github.com/mgerstner/squinnie',
        package_data = {
            # these paths are interpreted relative to the squinnie package.
            'squinnie': ['../etc/*.json']
        },
        classifiers = [
            'Intended Audience :: Developers',
            'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
            'Programming Language :: Python :: 2.7',
            'Topic :: Security'
        ],
        scripts = [ 'bin/squinnie' ]
    )
finally:
    try:
        if remove_rst:
            os.remove(readme_rst)
    except:
        pass
