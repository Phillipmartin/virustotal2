#!/usr/bin/env python

#TODO: fix tests

try:
    from setuptools import setup, Command

except:
    from distutils.core import setup, Command

import __init__ as virustotal2




class PyTest(Command):
    user_options = []
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import sys,subprocess
        errno = subprocess.call([sys.executable, 'virustotal2_test.py'])
        raise SystemExit(errno)

setup(
    name         = "virustotal2",
    description  = "Complete, Pythonic VirusTotal Public API 2.0 client",
    url          = "https://github.com/Phillipmartin/virustotal2",
    tests_require = ['pytest'],
    #cmdclass = {'test': PyTest},
    test_suite = ['pytest'],

    py_modules   = ["virustotal2"],
    requires     = ['pytest', 'requests'],
    classifiers  = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    license      = virustotal2.__license__,
    version      = virustotal2.__version__,
    author       = virustotal2.__author__,
    author_email = virustotal2.__email__,
)
