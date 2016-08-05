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

2.0.0 (Aug 5, 2016)
-------------------

* Major rewrite of how python-ntlm3 handles authentication
* Added support for NTLMv2 auth and fixed up some older auth methods
* Moved code to separate classes to help cleanup the code
* Added support for channel_bindings (CBT) - Hasn't been tested yet
* Removed some methods that weren't being used at all (most were starting to implement these features)
* More comments on each methods relating back to the MS-NLMP document pack on NTLM authentication for easier maintenance
* Created target_info.py to handle AV_PAIRS and putting it in the target info
* Renaming of some variables to match more closely with the Microsoft documentation, makes it easier to understand what is happening

Breaking Changes:
* parse_NTLM_CHALLENGE_MESSAGE in ntlm.py now returns the target_info values from the message, necessitating packages calling this to register this variable
* create_NTLM_AUTHENTICATE_MESSAGE in ntlm.py now supports three more variables:
    server_target_info (new var returned above),
    ntlm_compatiblity (default is 3), and
    channel_bindings (default is none)
    This should not break any packages as they have default values assigned but it is best to be careful
* A lot of the functions in ntlm.py have been moved as private methods in compute_response.py. These should not have been called by other packages as they are used to generate messages.

