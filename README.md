python-ntlm3
============
[![Build Status](https://travis-ci.org/trustrachel/python-ntlm3.svg?branch=master)](https://travis-ci.org/trustrachel/python-ntlm) [![Build status](https://ci.appveyor.com/api/projects/status/jtgb7bk5mavgysmq?svg=true)](https://ci.appveyor.com/project/trustrachel/python-ntlm3)
 [![Coverage Status](https://img.shields.io/coveralls/trustrachel/python-ntlm3.svg)](https://coveralls.io/r/trustrachel/python-ntlm3)

This is a Python 3 compatible fork of the [python-ntlm](https://code.google.com/p/python-ntlm) project. 

About this library
------------------

This library handles the low-level details of NTLM authentication. Almost all users should use [requests-ntlm](https://github.com/requests/requests-ntlm) instead, which is a plugin to requests that uses this library under the hood and is way easier to use and understand. 

Features
--------
* LM, NTLM and NTLMv1 authentication
* NTLM1 and NTLM2 extended session security
* Ability to set the The NTLM Compatibility level when sending messages
* Channel Binding Tokens (Need to verify this works but potentially it si there)

Installation
------------

python-ntlm3 supports Python 2.6, 2.7 and 3.3+ 

To install, use pip:

    pip install python-ntlm3

To install from source, download the source code, then run:

    python setup.py install
    
Usage
------------

This library has an identical API as python-ntlm and is a drop-in replacement. To use, include this:

    import ntlm3 as ntlm

API
----------

TODO


Backlog
-------
* Fix up NTLMv2 compute tests to work properly, need some mocking action for this
* Verify `channel_bindings` work correctly, find a way to test this as well
* Add support for session security signing and ecryption
* Migrate test_ntlm.py tests to use the Microsoft examples once the above is implemented
* Add support for MIC to enhance the security
* Simplify the 3 messages to their own classes, make it easier to structure and retrieve info
* Tidy up the negotiate and authenticate message flags used and the defaults set