Changes
=======

1.0.0 (Dec 16, 2014)
--------------------

Initial public offering.

1.0.1 (Dec 16, 2014)
--------------------

* Removed some logging that could spew passwords to the logfiles

1.0.2 (Jan 6, 2015)
-------------------

* Bugfix for windows (thanks to @rbcarson for the help)
* Added Appveyor continous integration testing on Windows to avoid these problems in future

1.1.0 (Aug 5, 2016)
-------------------

* Added support for Python 3.5
* Added requirement for cryptography so we can calculate RC4 values for EncryptedRandomSessionKey and signing and sealing (can we remove this dependency?)
* Major rewrite of how python-ntlm3 handles authentication
* Added support for NTLMv2 auth and fixed up some older auth methods
* Moved code to separate classes to help cleanup the code
* Added support for channel_bindings (CBT) when supplying a certificate hash
* Added support for MIC data for authenticate messages
* Preliminary support for signing and sealing of messages. Needs to be done outside of auth messages and tested more thoroughly
* Removed some methods that weren't being used at all (most were starting to implement these features above but weren't there)
* More comments on each methods relating back to the MS-NLMP document pack on NTLM authentication for easier maintenance
* Created target_info.py to handle AV_PAIRS and putting it in the target info
* Renaming of some variables to match more closely with the Microsoft documentation, makes it easier to understand what is happening
* Rewriting of tests to accommodate these new changes and to cover the new cases
* The methods `create_NTLM_NEGOTIATE_MESSAGE`, `parse_NTLM_CHALLENGE_MESSAGE`, `create_NTLM_AUTHENTICATE_MESSAGE` will no longer be supported in future version. They do not support NTLMv2 auth and are only left for compatibility