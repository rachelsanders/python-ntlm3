python-ntlm3
============
[![Build Status](https://travis-ci.org/trustrachel/python-ntlm3.svg?branch=master)](https://travis-ci.org/trustrachel/python-ntlm) [![Build status](https://ci.appveyor.com/api/projects/status/jtgb7bk5mavgysmq?svg=true)](https://ci.appveyor.com/project/trustrachel/python-ntlm3)
 [![Coverage Status](https://img.shields.io/coveralls/trustrachel/python-ntlm3.svg)](https://coveralls.io/r/trustrachel/python-ntlm3)

This is a Python 3 compatible fork of the [python-ntlm](https://code.google.com/p/python-ntlm) project. 

About this library
------------------

This library handles the low-level details of NTLM authentication. This library will create the 3 different message types in NTLM based on the input and produce a base64 encoded value to attach to the HTTP header.

The goal of this library is to offer full NTLM support including signing and sealing of messages as well as supporting MIC for message integrity and the ability to customise and set limits on the messages sent. Please see Features and Backlog for a list of what is and is not currently supported.

Features
--------
* LM, NTLM and NTLMv2 authentication
* NTLM1 and NTLM2 extended session security
* Set the The NTLM Compatibility level when sending messages
* Channel Binding Tokens support, need to pass in the SHA256 hash of the certificate for it to work
* Support for MIC to enhance the integrity of the messages
* (To be Tested) Support for session security with signing and sealing messages after authentication happens

Installation
------------

python-ntlm3 supports Python 2.6, 2.7 and 3.3+ 

To install, use pip:

    pip install python-ntlm3

To install from source, download the source code, then run:

    python setup.py install
    
Usage
------------

Almost all users should use [requests-ntlm](https://github.com/requests/requests-ntlm) instead of this library. The library requests-ntlm is a plugin that uses this library under the hood and provides an easier function to use and understand.

If you are set on using python-ntlm3 directly to compute the message structures this is a very basic outline of how it can be done. The code examples are psuedocode and should be adapted for your purpose.

When initliasing the ntlm context you will have to supply the NTLM compatibility level. The key difference between the different auth levels are the ntlm_compatibility variable supplied when initialising Ntlm. An overview of what each sets is below;
* `0` - LM Auth and NTLMv1 Auth
* `1` - LM Auth and NTLMv1 Auth with Extended Session Security (NTLM2)
* `2` - NTLMv1 Auth with Extended Session Security (NTLM2)
* `3` - NTLMv2 Auth (Default Choice)
* `4` - NTLMv2 Auth
* `5` - NTLMv2 Auth

Level 3 to 5 are the same from a client perspective but differ with how the server handles the auth which is outside this project's scope. This setting is set independently on that server so choosing 3, 4 or 5 when calling Ntlm will make no difference at all. See [LmCompatibilityLevel](https://technet.microsoft.com/en-us/library/cc960646.aspx) for more details.

Extended Session Security is a security feature designed to increase the security of LM and NTLMv1 auth. It is no substitution for NTLMv2 but is better than nothing and should be used if possible when you need NTLMv1 compatibility.

The variables required are outlined below;
* `user_name` - The username to authenticate with, should not have the domain prefix, i.e. USER not DOMAIN\\USER
* `password` - The password of the user to authenticate with
* `domain_name` - The domain of the user, i.e. DOMAIN. Can be blank if not in a domain environment
* `workstation` - The workstation you are running on. Can be blank if you do not wish to send this
* `server_certificate_hash` - (NTLMv2 only) The SHA256 hash of the servers DER encoded certificate. Used to calculate the Channel Binding Tokens and should be added even if it isn't required. Can be blank but auth will fail if the server requires this hash.


#### LM Auth/NTLMv1 Auth

LM and NTLMv1 Auth are older authentication methods that should be avoided where possible. Choosing between these authentication methods are almost identical expect where you specify the ntlm_compatiblity level.

```python
import socket

from ntlm3.ntlm import Ntlm

user_name = 'User'
password = 'Password'
domain_name = 'Domain' # Can be blank if you are not in a domain
workstation = socket.gethostname().upper() # Can be blank if you wish to not send this info

ntlm_context = Ntlm(ntlm_compatibility=0) # Put the ntlm_compatibility level here, 0-2 for LM Auth/NTLMv1 Auth
negotiate_message = ntlm_context.create_negotiate_message(domain_name, workstation).decode()

# Attach the negotiate_message to your NTLM/NEGOTIATE HTTP header and send to the server. Get the challenge response back from the server
challenge_message = http.response.headers['HEADERFIELD']

authenticate_message = ntlm_context.create_authenticate_message(user_name, password, domain_name, workstation).decode()

# Attach the authenticate_message ot your NTLM_NEGOTIATE HTTP header and send to the server. You are now authenticated with NTLMv1
```

#### NTLMv2

NTLMv2 Auth is the newest NTLM auth method from Microsoft and should be the option chosen by default unless you require an older auth method. The implementation is the same as NTLMv1 but with the addition of the optional `server_certificate_hash` variable and the `ntlm_compatibility` is not specified.

```python
import socket

from ntlm3.ntlm import Ntlm

user_name = 'User'
password = 'Password'
domain_name = 'Domain' # Can be blank if you are not in a domain
workstation = socket.gethostname().upper() # Can be blank if you wish to not send this info
server_certificate_hash = '96B2FC1EC30792619286A0C7FD62863E81A6564E72829CBC0A46F7B1D5D92A18' # Can be blank if you don't want CBT sent

ntlm_context = Ntlm()
negotiate_message = ntlm_context.create_negotiate_message(domain_name, workstation).decode()

# Attach the negotiate_message to your NTLM/NEGOTIATE HTTP header and send to the server. Get the challenge response back from the server
challenge_message = http.response.headers['HEADERFIELD']

authenticate_message = ntlm_context.create_authenticate_message(user_name, password, domain_name, workstation, server_certificate_hash).decode()

# Attach the authenticate_message ot your NTLM_NEGOTIATE HTTP header and send to the server. You are now authenticated with NTLMv1
```

#### Signing/Sealing

All version of NTLM supports signing (integrity) and sealing (confidentiality) of message content. This function can add these improvements to a message that is sent and received from the server. While it does encrypt the data if supported by the server it is only done with RC4 with a 128-bit key which is not very secure and on older systems this key length could be 56 or 40 bit. This functionality while tested and conforms with the Microsoft documentation has yet to be fully tested in an integrated environment. Once again this has not been thoroughly tested and has only passed unit tests and their expections.

```python
import socket

from ntlm3.ntlm import Ntlm

user_name = 'User'
password = 'Password'
domain_name = 'Domain' # Can be blank if you are not in a domain
workstation = socket.gethostname().upper() # Can be blank if you wish to not send this info
msg_data = "Message to send to the server"
server_certificate_hash = '96B2FC1EC30792619286A0C7FD62863E81A6564E72829CBC0A46F7B1D5D92A18' # Can be blank if you don't want CBT sent

ntlm_context = Ntlm()
negotiate_message = ntlm_context.create_negotiate_message(domain_name, workstation).decode()

# Attach the negotiate_message to your NTLM/NEGOTIATE HTTP header and send to the server. Get the challenge response back from the server
challenge_message = http.response.headers['HEADERFIELD']

authenticate_message = ntlm_context.create_authenticate_message(user_name, password, domain_name, workstation, server_certificate_hash).decode()

if ntlm_context.session_security is None:
    raise Exception("Server does not support signing and sealing")
else:
    session_security = ntlm_context.session_security

# Encrypt the msg with the sealing function and send the message
msg_data, msg_signature = session_security.wrap(msg_data)
request.body = msg_data
request.header = "NTLM %s" % authenticate_message
request.send

# Receive the response the from the server
response_msg = response.body[bodyindex]
response_signature = response.body[signatureindex]
response_msg = session_security.unwrap(response_msg, response_signature)
```

Deprecated methods
------------------

As of version 1.1.0 the methods `create_NTLM_NEGOTIATE_MESSAGE`, `parse_NTLM_CHALLENGE_MESSAGE`, `create_NTLM_AUTHENTICATE_MESSAGE` in ntlm.py have been deprecated and will be removed from the next major version of python-ntlm3.

Please use the Ntlm class in ntlm.py in the future as this brings supports for NTLMv2 authentication and more control over how your messages are sent. Ntlm is also easier to use and understand with the various methods being moved to classes of their own and will potentially allow support for more features such as signing and sealing.


Backlog
-------
* Remove the old ntlm.py code that has been left there for compatibility in the next major version release. This does not support NTLMv2 auth
* Fully test out signing and sealing of messages over the wire with another library
* Automatically get windows version if running on windows, use default if not that case
* Add param when initialising the ntlm context to throw an exception and cancel auth if the server doesn't support 128-bit keys for sealing
* Add param when initialising the ntlm context to not send the MIC structure for older servers
* Add param to independently verify the target name returned from the server and the value passed in