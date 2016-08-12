# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

import base64
import socket
from ntlm3.constants import NegotiateFlags
from ntlm3.messages import NegotiateMessage, ChallengeMessage, AuthenticateMessage

"""
utility functions for Microsoft NTLM authentication

References:
[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf

[MS-NTHT]: NTLM Over HTTP Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NTHT%5D.pdf

Cntlm Authentication Proxy
http://cntlm.awk.cz/

NTLM Authorization Proxy Server
http://sourceforge.net/projects/ntlmaps/

Optimized Attack for NTLM2 Session Response
http://www.blackhat.com/presentations/bh-asia-04/bh-jp-04-pdfs/bh-jp-04-seki.pdf
"""

class Ntlm(object):
    """
    Initialises the NTLM context to use when sending and receiving messages to and from the server. You should be
    using this object as it supports NTLMv2 authenticate and it easier to use than before. It should also potentially
    make it eaiser to support signing and sealing of messages as well as a MIC structure in the future as the
    Authentication message now has easy access to both the Negotiate and Challenge messages used previously.

    :param ntlm_compatibility: The Lan Manager Compatibility Level to use withe the auth message - Default 3
                                    This is set by an Administrator in the registry key
                                    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
                                    The values correspond to the following;
                                    0 : Clients use LM and NTLM authentication, but they never use NTLMv2 session security.
                                        Domain controllers accept LM, NTLM, and NTLMv2 authentication.
                                    1 : Clients use LM and NTLM authentication, and they use NTLMv2 session security if the
                                        server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
                                    2 : Clients use only NTLM authentication, and they use NTLMv2 (NTLM2 in this code) session
                                        security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication.
                                    3 : Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server
                                        supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.
                                    4 : Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server
                                        supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2
                                    5 : Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server
                                        supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2.
    :param session_security: ['none', 'sign', 'seal'] Setting to set if we want to sign, seal(encrypt) or do nothing with our messages.
                                    Only none is implemented right now
    :param use_oem_encoding: Whether we want to use oem encoding (old encoding) for our AUTHENTICATE_MESSAGES, default is False
    :param use_version_debug: Whether we want to sent the version info for debugging purposes, default if False
    :param use_128_key: Whether we want to 128-bit keys (True) when sealing our messages or 56-bit (False), default is True
    """
    def __init__(self, ntlm_compatibility=3, session_security='none', use_oem_encoding=False, use_version_debug=False, use_128_key=True):
        self.ntlm_compatibility = ntlm_compatibility

        # Setting up our flags so the challenge message returns the target info block if supported
        self.negotiate_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO

        # Setting the message types based on the ntlm_compatibility level
        self._set_ntlm_compatibility_flags(self.ntlm_compatibility)

        # TODO: Add support for setting the key bit level, need session_security seal and sign
        # Setting the key length to 128-bit unless otherwise stated
        #if use_128_key:
        #    self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_128
        #else:
        #    self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_56

        # Sets the encoding type flag based on a passed in parameter
        if use_oem_encoding == True:
            self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM
        else:
            self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE

        # Set the version number in the messages if the debug flag is set
        if use_version_debug == True:
            self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION

        # Check the session_security flags
        self._set_session_security(session_security)


    def create_negotiate_message(self, domain_name=None, workstation=None):
        """
        Create an NTLM NEGOTIATE_MESSAGE

        :param domain_name: The domain name of the user account we are authenticating with, default is None
        :param worksation: The workstation we are using to authenticate with, default is None
        :return: A base64 encoded string of the NEGOTIATE_MESSAGE
        """
        self.negotiate_message = NegotiateMessage(self.negotiate_flags, domain_name, workstation)

        return base64.b64encode(self.negotiate_message.get_data())

    def parse_challenge_message(self, msg2):
        """
        Parse the NTLM CHALLENGE_MESSAGE from the server and add it to the Ntlm context fields
        :param msg2: A base64 encoded string of the CHALLENGE_MESSAGE
        """
        msg2 = base64.b64decode(msg2)
        self.challenge_message = ChallengeMessage(msg2)

    def create_authenticate_message(self, user_name, password, domain_name=None, workstation=None, server_certificate_hash=None):
        """
        Create an NTLM AUTHENTICATE_MESSAGE based on the Ntlm context and the previous messages sent and received
        :param user_name: The user name of the user we are trying to authenticate with
        :param password: The password of the user we are trying to authenticate with
        :param domain_name: The domain name of the user account we are authenticated with, default is None
        :param workstation: The workstation we are using to authenticate with, default is None
        :param server_certificate_hash: The SHA256 hash string of the server certificate (DER encoded) NTLM is authenticating to. Used for Channel
                                        Binding Tokens. If nothing is supplied then the CBT hash will not be sent. See messages.py AuthenticateMessage
                                        for more details
        :return: A base64 encoded string of the AUTHENTICATE_MESSAGE
        """
        self.authenticate_message = AuthenticateMessage(user_name, password, domain_name, workstation, self.challenge_message, self.ntlm_compatibility, server_certificate_hash)

        return base64.b64encode(self.authenticate_message.get_data())


    def _set_ntlm_compatibility_flags(self, ntlm_compatibility):
        if (ntlm_compatibility >= 0) and (ntlm_compatibility <= 5):
            if ntlm_compatibility == 0:
                self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
                                        NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
            elif ntlm_compatibility == 1:
                self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
                                        NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            else:
                self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        else:
            raise Exception("Unknown ntlm_compatibility level - expecting value between 0 and 5")

    def _set_session_security(self, session_security):
        if session_security not in ('none'): #TODO: Add sign and seal to the checks once that support has been added
            raise Exception("session_security must be 'none'")

        # TODO: Add support for message signing
        # Add signing to the message if the session_security is set to sign
        #if session_security == 'sign':
        #    self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | \
        #                            NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
        #                            NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN

        # TODO: Add support for message sealing
        # Add encryption support to the emssage if the session_security is set to seal
        #if session_security == 'seal':
        #    self.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | \
        #                            NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
        #                            NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
        #                            NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL




"""
    The following functions and variables are only here for compatibility purposes. They are now deprecated as they
    do not allow support for NTLMv2 authentication and the benefits that brings. Please note these will hopefully be
    deleted sometime in the future and are only here to bridge older applications still using the older methods and
    make it easier for them to switch to the newer structure above.
"""
NTLM_TYPE1_FLAGS = (NegotiateFlags.NTLMSSP_NEGOTIATE_OEM |
                    NegotiateFlags.NTLMSSP_REQUEST_TARGET |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION)

NTLM_TYPE2_FLAGS = (NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                    NegotiateFlags.NTLMSSP_REQUEST_TARGET |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION)

def create_NTLM_NEGOTIATE_MESSAGE(user, type1_flags=NTLM_TYPE1_FLAGS):
    ntlm_context = Ntlm(**{"ntlm_compatibility": 2})
    ntlm_context.negotiate_flags = type1_flags
    user_parts = user.split('\\', 1)
    domain_name = user_parts[0].upper()
    workstation = socket.gethostname().upper()

    msg1 = ntlm_context.create_negotiate_message(domain_name, workstation)

    return msg1

def parse_NTLM_CHALLENGE_MESSAGE(msg2):
    ntlm_context = Ntlm(**{"ntlm_compatibility": 2})
    ntlm_context.parse_challenge_message(msg2)

    return (ntlm_context.challenge_message.server_challenge, ntlm_context.challenge_message.negotiate_flags)

def create_NTLM_AUTHENTICATE_MESSAGE(nonce, user, domain, password, NegotiateFlags):
    ntlm_context = Ntlm(**{"ntlm_compatibility": 2})
    ntlm_context.negotiate_flags = NTLM_TYPE2_FLAGS
    workstation = socket.gethostname().upper()

    """
    This is a dodgy hack to set up a ChallengeMessage object from the Microsoft example.
    We then overwrite the server_challenge, negotiate_flags and version field with what
    we get normally. This is because create_authenticate_message need these fields to work
    and this is the only way to get that compatibility in
    """
    ntlm_context.parse_challenge_message('TlRMTVNTUAACAAAADAAMADgAAAAzggqCASNFZ4mrze8AAAAAAAAAAAAAAAAAAAAABgBwFwAAAA9TAGUAcgB2AGUAcg==')
    ntlm_context.challenge_message.server_challenge = nonce
    ntlm_context.challenge_message.negotiate_flags = NTLM_TYPE2_FLAGS
    ntlm_context.challenge_message.version = None

    msg3 = ntlm_context.create_authenticate_message(user, password, domain, workstation)

    return msg3