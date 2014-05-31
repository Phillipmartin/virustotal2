#!/usr/bin/env python

#TODO: fix tests

try:
    from setuptools import setup

except:
    from distutils.core import setup
import sys
from setuptools.command.test import test as TestCommand
import __init__ as virustotal2



class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

setup(
    name         = "virustotal2",
    description  = "Complete, Pythonic VirusTotal Public API 2.0 client",
    url          = "https://github.com/Phillipmartin/virustotal2",
    tests_require = ['pytest'],
    cmdclass = {'test': PyTest},

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
