python-ntlm3
============
[![Build Status](https://travis-ci.org/trustrachel/python-ntlm3.svg?branch=master)](https://travis-ci.org/trustrachel/python-ntlm) [![Coverage Status](https://img.shields.io/coveralls/trustrachel/python-ntlm3.svg)](https://coveralls.io/r/trustrachel/python-ntlm3)

This is a Python 3 compatible fork of the [python-ntlm](https://code.google.com/p/python-ntlm) project. 

About this library
------------------

This library handles the low-level details of NTLM authentication. Most users will want to use [requests-ntlm](https://github.com/requests/requests-ntlm), which is a plugin to requests that [*will use, pull request pending] uses this library under the hood. 

Installation
------------

python-ntlm3 supports Python 2.6, 2.7 and 3.3+ 

To install, use pip:

    pip install python-ntlm3

To install from source, download the source code, then run:

    python setup.py install
    
Usage
------------

This library has an identical api to python-ntlm and should be a drop-in replacement. To use, include this:

    import ntlm3 as ntlm

[TODO - add more usage here on how to use it]
