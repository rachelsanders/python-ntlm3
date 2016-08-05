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

import struct
import base64
from socket import gethostname
from ntlm3.constants import NegotiateFlags, MessageTypes, NTLM_SIGNATURE
from ntlm3.target_info import TargetInfo
from ntlm3.compute_response import ComputeResponse

# we send these flags with our type 1 message
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

"""
    [MS-NLMP] v28.0 2016-07-14

    2.2.1.1 NEGOTIATE_MESSAGE
    The NEGOTIATE_MESSAGE defines an NTLM Negotiate message that is sent from the client to
    the server. This message allows the client to specify its supported NTLM options to
    the server.

   type1_flags not used, for compatibility
"""
def create_NTLM_NEGOTIATE_MESSAGE(user, type1_flags=NTLM_TYPE1_FLAGS):
    expected_body_length = 40
    payload_offset = expected_body_length

    # Gettings values in input into the message
    domain_name = user.split('\\', 1)[0].upper().encode('ascii')
    workstation = gethostname().upper().encode('ascii')

    # Setting the values for the message
    signature = NTLM_SIGNATURE
    message_type = struct.pack('<L', MessageTypes.NTLM_NEGOTIATE)
    negotiate_flags = struct.pack('<I', type1_flags)

    # DomainNameFields - 8 bytes
    domain_name_len = struct.pack('<H', len(domain_name))
    domain_name_max_len = struct.pack('<H', len(domain_name))
    domain_name_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(domain_name)

    # WorkstationFields - 8 bytes
    workstation_len = struct.pack('<H', len(workstation))
    workstation_max_len = struct.pack('<H', len(workstation))
    workstation_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(workstation)

    # Version Fields - 8 bytes
    # TODO: Get the major and minor version of Windows instead of using default values
    product_major_version = struct.pack('<B', 5)
    product_minor_version = struct.pack('<B', 1)
    product_build = struct.pack('<H', 2600)
    version_reserved = b'\0' * 3
    ntlm_revision_current = struct.pack('<B', 15)

    # Payload - variable length
    payload = domain_name + workstation

    # Bring the header values together into 1 message
    msg1 = signature + message_type + negotiate_flags + \
        domain_name_len + domain_name_max_len + domain_name_buffer_offset + \
        workstation_len + workstation_max_len + workstation_buffer_offset + \
        product_major_version + product_minor_version + product_build + \
        version_reserved + ntlm_revision_current

    assert expected_body_length == len(msg1), "BODY_LENGTH: %d != msg1: %d" % (expected_body_length, len(msg1))

    # Adding the payload data to the message
    msg1 += payload
    msg1 = base64.b64encode(msg1)

    return msg1

"""
    [MS-NLMP] v28.0 2016-07-14

    2.2.1.2 CHALLENGE_MESSAGE
    The CHALLENGE_MESSAGE defines an NTLM challenge message that is sent from the server to
    the client. The CHALLENGE_MESSAGE is used by the server to challenge the client to prove
    its identity, For connection-oriented requests, the CHALLENGE_MESSAGE generated by the
    server is in response to the NEGOTIATE_MESSAGE from the client.
"""
def parse_NTLM_CHALLENGE_MESSAGE(msg2):
    msg2 = base64.b64decode(msg2)

    # Getting the values from the CHALLENGE_MESSAGE
    signature = msg2[0:8]
    assert signature == NTLM_SIGNATURE

    message_type = struct.unpack("<I", msg2[8:12])[0]
    assert message_type == MessageTypes.NTLM_CHALLENGE

    # TargetName Fields
    target_name_len = struct.unpack("<H", msg2[12:14])[0]
    target_name_max_len = struct.unpack("<H", msg2[14:16])[0]
    target_name_buffer_offset = struct.unpack("<I", msg2[16:20])[0]

    negotiate_flags = struct.unpack("<I", msg2[20:24])[0]
    server_challenge = msg2[24:32]
    reserved = msg2[32:40]

    if negotiate_flags & NegotiateFlags.NTLMSSP_REQUEST_TARGET:
        target_name = msg2[target_name_buffer_offset:target_name_buffer_offset + target_name_len]

    if negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO:
        # TargetInfo Fields
        target_info_len = struct.unpack("<H", msg2[40:42])[0]
        target_info_max_len = struct.unpack("<H", msg2[42:44])[0]
        target_info_buffer_offset = struct.unpack("<I", msg2[44:48])[0]

        target_info_raw = msg2[target_info_buffer_offset:target_info_buffer_offset + target_info_len]
        target_info = TargetInfo(target_info_raw)
    else:
        target_info = None

    return (server_challenge, negotiate_flags, target_info)

"""
    [MS-NLMP] v28.0 2016-07-14

    2.2.1.3 AUTHENTICATE_MESSAGE
    The AUTHENTICATE_MESSAGE defines an NTLM authenticate message that is sent from the
    client to the server after the CHALLENGE_MESSAGE is processed by the client.

    param: challenge_target_info - The target_info returned by the challenge message, used for NTLMv2 auth for calculation
    param: ntlm_compatibility - The Lan Manager Compatibility Level to use - See compute_response.py for mor einfo
"""
def create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, user, domain, password, server_negotiate_flags, server_target_info=None, ntlm_compatibility=3, channel_bindings=None):
    expected_body_length = 72
    payload_offset = expected_body_length

    # Getting values in input into the message
    if (server_negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE):
        domain_name = domain.upper().encode('utf-16-le')
        user_name = user.encode('utf-16-le')
        workstation = gethostname().upper().encode('utf-16-le')

        # TODO: Implement signing and sealing of NTLM messages
        encrypted_random_session_key = "".encode('utf-16-le')
    else:
        domain_name = domain.upper().encode('ascii')
        user_name = user.encode('ascii')
        workstation = gethostname().upper().encode('ascii')

        # TODO: Implement signing and sealing of NTLM messages
        encrypted_random_session_key = b""

    compute_response = ComputeResponse(server_negotiate_flags, domain, user_name, password, server_challenge, server_target_info, ntlm_compatibility)
    # Get the nt_challenge_response based on the NTLM version used and the flags set. This will also return the target_info sent to the client used when calculating the lm_challenge_response
    (nt_challenge_response, client_target_info) = compute_response.get_nt_challenge_response(channel_bindings)

    # Get the lm_challenge_response based on the NTLM version used and the flags set.
    lm_challenge_response = compute_response.get_lm_challenge_response()

    # Setting the values for the message
    signature = NTLM_SIGNATURE
    message_type = struct.pack('<I', MessageTypes.NTLM_AUTHENTICATE)
    negotiate_flags = struct.pack('<I', NTLM_TYPE2_FLAGS)

    # LmChallengeResponseFields - 8 bytes
    lm_challenge_response_len = struct.pack('<H', len(lm_challenge_response))
    lm_challenge_response_max_len = struct.pack('<H', len(lm_challenge_response))
    lm_challenge_response_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(lm_challenge_response)

    # NtChallengeResponseFields - 8 bytes
    nt_challenge_response_len = struct.pack('<H', len(nt_challenge_response))
    nt_challenge_response_max_len = struct.pack('<H', len(nt_challenge_response))
    nt_challenge_response_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(nt_challenge_response)

    # DomainNameFields - 8 bytes
    domain_name_len = struct.pack('<H', len(domain_name))
    domain_name_max_len = struct.pack('<H', len(domain_name))
    domain_name_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(domain_name)

    # UserNameFields - 8 bytes
    user_name_len = struct.pack('<H', len(user_name))
    user_name_max_len = struct.pack('<H', len(user_name))
    user_name_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(user_name)

    # WorkstatonFields - 8 bytes
    workstation_len = struct.pack('<H', len(workstation))
    workstation_max_len = struct.pack('<H', len(workstation))
    workstation_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(workstation)

    # EncryptedRandomSessionKeyFields - 8 bytes
    encrypted_random_session_key_len = struct.pack('<H', len(encrypted_random_session_key))
    encrypted_random_session_key_max_len = struct.pack('<H', len(encrypted_random_session_key))
    encrypted_random_session_key_buffer_offset = struct.pack('<I', payload_offset)
    payload_offset += len(encrypted_random_session_key)

    # Version Fields - 8 bytes
    # TODO: Get the major and minor version of Windows instead of using default values
    product_major_version = struct.pack('<B', 5)
    product_minor_version = struct.pack('<B', 1)
    product_build = struct.pack('<H', 2600)
    version_reserved = b'\0' * 3
    ntlm_revision_current = struct.pack('<B', 15)

    # TODO - Add support for message signing and sealing to utilise the MIC value
    mic = struct.pack('<IIII', 0, 0, 0, 0)

    # Payload - variable length
    payload = lm_challenge_response + nt_challenge_response + domain_name + \
        user_name + workstation + encrypted_random_session_key

    # Bring the header values together into 1 message
    msg3 = signature + message_type + \
        lm_challenge_response_len + lm_challenge_response_max_len + lm_challenge_response_buffer_offset + \
        nt_challenge_response_len + nt_challenge_response_max_len + nt_challenge_response_buffer_offset + \
        domain_name_len + domain_name_max_len + domain_name_buffer_offset + \
        user_name_len + user_name_max_len + user_name_buffer_offset + \
        workstation_len + workstation_max_len + workstation_buffer_offset + \
        encrypted_random_session_key_len + encrypted_random_session_key_max_len + encrypted_random_session_key_buffer_offset + \
        negotiate_flags + \
        product_major_version + product_minor_version + product_build + \
        version_reserved + ntlm_revision_current

    assert expected_body_length == len(msg3), "BODY_LENGTH: %d != msg3: %d" % (expected_body_length, len(msg3))

    msg3 += payload
    msg3 = base64.b64encode(msg3)
    return msg3