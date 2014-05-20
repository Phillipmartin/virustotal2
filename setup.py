#!/usr/bin/env python

#TODO: fix tests

try:
    from setuptools import setup

except:
    from distutils.core import setup

import __init__ as virustotal2

setup(
    name         = "virustotal2",
    description  = "Complete, Pythonic VirusTotal Public API 2.0 client",
    url          = "https://github.com/Phillipmartin/virustotal2",
    test_suite   = "virustotal2_tests",

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
