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
from ntlm3.constants import NegotiateFlags, MessageTypes, NTLM_SIGNATURE
from ntlm3.target_info import TargetInfo
from ntlm3.compute_response import ComputeResponse

class NegotiateMessage(object):
    EXPECTED_BODY_LENGTH = 40

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.1.1 NEGOTIATE_MESSAGE
        The NEGOTIATE_MESSAGE defines an NTLM Negotiate message that is sent from the client to
        the server. This message allows the client to specify its supported NTLM options to
        the server.

        :param negotiate_flags: A NEGOTIATE structure that contains a set of bit flags. These flags are the options the client supports
        :param domain_name: The domain name of the user to authenticate with, default is None
        :param workstation: The worksation of the client machine, default is None

        Attributes:
            signature: An 8-byte character array that MUST contain the ASCII string 'NTLMSSP\0'
            message_type: A 32-bit unsigned integer that indicates the message type. This field must be set to 0x00000001
            negotiate_flags: A NEGOTIATE strucutre that contains a set of bit flags. These flags are the options the client supports
            version: Contains the windows version info of the client. It is used only debugging purposes and are only set when NTLMSSP_NEGOTIATE_VERSION flag is set
            domain_name: A byte-array that contains the name of the client authentication domain that MUST Be encoded in the negotiated character set
            workstation: A byte-array that contains the name of the client machine that MUST Be encoded in the negotiated character set
    """
    def __init__(self, negotiate_flags, domain_name, workstation):
        self.signature = NTLM_SIGNATURE
        self.message_type = struct.pack('<L', MessageTypes.NTLM_NEGOTIATE)

        # Check if the domain_name value is set, if it is, make sure the negotiate_flag is also set
        if domain_name == None:
            self.domain_name = ''
        else:
            self.domain_name = domain_name
            negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED

        # Check if the workstation value is set, if it is, make sure the negotiate_flag is also set
        if workstation == None:
            self.workstation = ''
        else:
            self.workstation = workstation
            negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

        # Set the encoding flag to use OEM, remove UNICODE if set as it isn't support in this message
        negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE
        negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM
        self.domain_name = self.domain_name.encode('ascii')
        self.workstation = self.workstation.encode('ascii')

        self.version = get_version(negotiate_flags)

        self.negotiate_flags = struct.pack('<I', negotiate_flags)

    def get_data(self):
        payload_offset = self.EXPECTED_BODY_LENGTH

        # DomainNameFields - 8 bytes
        domain_name_len = struct.pack('<H', len(self.domain_name))
        domain_name_max_len = struct.pack('<H', len(self.domain_name))
        domain_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.domain_name)

        # WorkstationFields - 8 bytes
        workstation_len = struct.pack('<H', len(self.workstation))
        workstation_max_len = struct.pack('<H', len(self.workstation))
        workstation_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.workstation)

        # Payload - variable length
        payload = self.domain_name + self.workstation

        # Bring the header values together into 1 message
        msg1 = self.signature
        msg1 += self.message_type
        msg1 += self.negotiate_flags
        msg1 += domain_name_len
        msg1 += domain_name_max_len
        msg1 += domain_name_buffer_offset
        msg1 += workstation_len
        msg1 += workstation_max_len
        msg1 += workstation_buffer_offset
        msg1 += self.version

        assert self.EXPECTED_BODY_LENGTH == len(msg1), "BODY_LENGTH: %d != msg1: %d" % (self.EXPECTED_BODY_LENGTH, len(msg1))

        # Adding the payload data to the message
        msg1 += payload
        return msg1

class ChallengeMessage(object):
    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.1.2 CHALLENGE_MESSAGE
        The CHALLENGE_MESSAGE defines an NTLM challenge message that is sent from the server to
        the client. The CHALLENGE_MESSAGE is used by the server to challenge the client to prove
        its identity, For connection-oriented requests, the CHALLENGE_MESSAGE generated by the
        server is in response to the NEGOTIATE_MESSAGE from the client.

        :param msg2: The CHALLENGE_MESSAGE received from the server after sending our NEGOTIATE_MESSAGE. This has
                        been decoded from a base64 string

        Attributes
            signature: An 8-byte character array that MUST contain the ASCII string 'NTLMSSP\0'
            message_type: A 32-bit unsigned integer that indicates the message type. This field must be set to 0x00000002
            negotiate_flags: A NEGOTIATE strucutre that contains a set of bit flags. The server sets flags to indicate options it supports
            server_challenge: A 64-bit value that contains the NTLM challenge. The challenge is a 64-bit nonce. Used in the AuthenticateMessage message
            reserved: An 8-byte array whose elements MUST be zero when sent and MUST be ignored on receipt
            version: When NTLMSSP_NEGOTIATE_VERSION flag is set in negotiate_flags field which contains the windows version info. Used only for debugging purposes
            target_name: When NTLMSSP_REQUEST_TARGET is set is a byte array that contains the name of the server authentication realm. In a domain environment this is the domain name not server name
            target_info: When NTLMSSP_NEGOTIATE_TARGET_INFO is set is a byte array that contains a sequence of AV_PAIR structures (target_info.py)
    """
    def __init__(self, msg2):
        # Setting the object values from the raw_challenge_message
        self.signature = msg2[0:8]
        self.message_type = struct.unpack("<I", msg2[8:12])[0]
        self.negotiate_flags = struct.unpack("<I", msg2[20:24])[0]
        self.server_challenge = msg2[24:32]
        self.reserved = msg2[32:40]

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION:
            self.version = struct.unpack("<q", msg2[48:56])[0]
        else:
            self.version = None

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_REQUEST_TARGET:
            target_name_len = struct.unpack("<H", msg2[12:14])[0]
            target_name_max_len = struct.unpack("<H", msg2[14:16])[0]
            target_name_buffer_offset = struct.unpack("<I", msg2[16:20])[0]
            self.target_name = msg2[target_name_buffer_offset:target_name_buffer_offset + target_name_len]
        else:
            self.target_name = None

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO:
            target_info_len = struct.unpack("<H", msg2[40:42])[0]
            target_info_max_len = struct.unpack("<H", msg2[42:44])[0]
            target_info_buffer_offset = struct.unpack("<I", msg2[44:48])[0]

            target_info_raw = msg2[target_info_buffer_offset:target_info_buffer_offset + target_info_len]
            self.target_info = TargetInfo(target_info_raw)
        else:
            self.target_info = None

        # Verify initial integrity of the message, it matches what should be there
        assert self.signature == NTLM_SIGNATURE
        assert self.message_type == MessageTypes.NTLM_CHALLENGE

    def get_target_name(self):
        payload_offset = self.EXPECTED_BODY_LENGTH

        # DomainNameFields - 8 bytes
        domain_name_len = struct.pack('<H', len(self.domain_name))
        domain_name_max_len = struct.pack('<H', len(self.domain_name))
        domain_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.domain_name)

        # WorkstationFields - 8 bytes
        workstation_len = struct.pack('<H', len(self.workstation))
        workstation_max_len = struct.pack('<H', len(self.workstation))
        workstation_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.workstation)

        # Payload - variable length
        payload = self.domain_name + self.workstation

        # Bring the header values together into 1 message
        msg1 = self.signature
        msg1 += self.message_type
        msg1 += self.negotiate_flags
        msg1 += domain_name_len
        msg1 += domain_name_max_len
        msg1 += domain_name_buffer_offset
        msg1 += workstation_len
        msg1 += workstation_max_len
        msg1 += workstation_buffer_offset
        msg1 += self.version

        assert self.EXPECTED_BODY_LENGTH == len(msg1), "BODY_LENGTH: %d != msg1: %d" % (
        self.EXPECTED_BODY_LENGTH, len(msg1))

        # Adding the payload data to the message
        msg1 += payload
        return msg1

class AuthenticateMessage(object):
    EXPECTED_BODY_LENGTH = 72

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.1.3 AUTHENTICATE_MESSAGE
        The AUTHENTICATE_MESSAGE defines an NTLM authenticate message that is sent from the
        client to the server after the CHALLENGE_MESSAGE is processed by the client.

        :param user_name: The user name of the user we are trying to authenticate with
        :param password: The password of the user we are trying to authenticate with
        :param domain_name: The domain name of the user account we are authenticated with, default is None
        :param workstation: The workstation we are using to authenticate with, default is None
        :param challenge_message: A ChallengeMessage object that was received from the server after the negotiate_message
        :param ntlm_compatibility: The Lan Manager Compatibility Level, used to determine what NTLM auth version to use, see Ntlm in ntlm.py for more details
        :param server_certificate_hash: The SHA256 hash string of the server certificate (DER encoded) NTLM is authenticating to. This is used to add
                                          to the gss_channel_bindings_struct for Channel Binding Tokens support. If none is passed through then python-ntlm3
                                          will not use Channel Binding Tokens when authenticating with the server which could cause issues if it is set to
                                          only authenticate when these are present. This is only used for NTLMv2 authentication.

        Attributes:
            signature: An 8-byte character array that MUST contain the ASCII string 'NTLMSSP\0'
            message_type: A 32-bit unsigned integer that indicates the message type. This field must be set to 0x00000003
            negotiate_flags: A NEGOTIATE strucutre that contains a set of bit flags. These flags are the choices the client has made from the CHALLENGE_MESSAGE options
            version: Contains the windows version info of the client. It is used only debugging purposes and are only set when NTLMSSP_NEGOTIATE_VERSION flag is set
            mic: The message integrity for the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE
            lm_challenge_response: An LM_RESPONSE of LMv2_RESPONSE structure that contains the computed LM response to the challenge
            nt_challenge_response: An NTLM_RESPONSE or NTLMv2_RESPONSE structure that contains the computed NT response to the challenge
            domain_name: The domain or computer name hosting the user account, MUST be encoded in the negotiated character set
            user_name: The name of the user to be authenticated, MUST be encoded in the negotiated character set
            workstation: The name of the computer to which the user is logged on, MUST Be encoded in the negotiated character set
            encrypted_random_session_key: The client's encrypted random session key
    """
    def __init__(self, user_name, password, domain_name, workstation, challenge_message, ntlm_compatibility, server_certificate_hash):
        self.signature = NTLM_SIGNATURE
        self.message_type = struct.pack('<L', MessageTypes.NTLM_AUTHENTICATE)
        self.negotiate_flags = challenge_message.negotiate_flags
        self.version = get_version(self.negotiate_flags)

        # TODO: Add support to use MIC for message integrity
        self.mic = struct.pack('<IIII', 0, 0, 0, 0)

        if domain_name == None:
            self.domain_name = ''
        else:
            self.domain_name = domain_name.upper()

        if workstation == None:
            self.workstation = ''
        else:
            self.workstation = workstation.upper()

        self.encrypted_random_session_key = ''
        # TODO: add support for sign and seal
        #if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH:
        #    self.encrypted_random_session_key = ''
        #else:
        #    self.encrypted_random_session_key = ''

        if self.negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE:
            encoding_value = 'utf-16-le'
        else:
            encoding_value = 'ascii'

        self.domain_name = self.domain_name.encode(encoding_value)
        self.user_name = user_name.encode(encoding_value)
        self.workstation = self.workstation.encode(encoding_value)
        self.encrypted_random_session_key = self.encrypted_random_session_key.encode(encoding_value)

        compute_response = ComputeResponse(self.user_name, password, self.domain_name, challenge_message,
                                           ntlm_compatibility)
        self.lm_challenge_response = compute_response.get_lm_challenge_response()
        self.nt_challenge_response = compute_response.get_nt_challenge_response(server_certificate_hash)
        self.negotiate_flags = struct.pack('<I', self.negotiate_flags)

    def get_data(self):
        payload_offset = self.EXPECTED_BODY_LENGTH

        # LmChallengeResponseFields - 8 bytes
        lm_challenge_response_len = struct.pack('<H', len(self.lm_challenge_response))
        lm_challenge_response_max_len = struct.pack('<H', len(self.lm_challenge_response))
        lm_challenge_response_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.lm_challenge_response)

        # NtChallengeResponseFields - 8 bytes
        nt_challenge_response_len = struct.pack('<H', len(self.nt_challenge_response))
        nt_challenge_response_max_len = struct.pack('<H', len(self.nt_challenge_response))
        nt_challenge_response_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.nt_challenge_response)

        # DomainNameFields - 8 bytes
        domain_name_len = struct.pack('<H', len(self.domain_name))
        domain_name_max_len = struct.pack('<H', len(self.domain_name))
        domain_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.domain_name)

        # UserNameFields - 8 bytes
        user_name_len = struct.pack('<H', len(self.user_name))
        user_name_max_len = struct.pack('<H', len(self.user_name))
        user_name_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.user_name)

        # WorkstatonFields - 8 bytes
        workstation_len = struct.pack('<H', len(self.workstation))
        workstation_max_len = struct.pack('<H', len(self.workstation))
        workstation_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.workstation)

        # EncryptedRandomSessionKeyFields - 8 bytes
        encrypted_random_session_key_len = struct.pack('<H', len(self.encrypted_random_session_key))
        encrypted_random_session_key_max_len = struct.pack('<H', len(self.encrypted_random_session_key))
        encrypted_random_session_key_buffer_offset = struct.pack('<I', payload_offset)
        payload_offset += len(self.encrypted_random_session_key)

        # Payload - variable length
        payload = self.lm_challenge_response + self.nt_challenge_response + self.domain_name + \
                  self.user_name + self.workstation + self.encrypted_random_session_key

        msg3 = self.signature
        msg3 += self.message_type
        msg3 += lm_challenge_response_len + lm_challenge_response_max_len + lm_challenge_response_buffer_offset
        msg3 += nt_challenge_response_len + nt_challenge_response_max_len + nt_challenge_response_buffer_offset
        msg3 += domain_name_len + domain_name_max_len + domain_name_buffer_offset
        msg3 += user_name_len + user_name_max_len + user_name_buffer_offset
        msg3 += workstation_len + workstation_max_len + workstation_buffer_offset
        msg3 += encrypted_random_session_key_len + encrypted_random_session_key_max_len + encrypted_random_session_key_buffer_offset
        msg3 += self.negotiate_flags
        msg3 += self.version

        assert self.EXPECTED_BODY_LENGTH == len(msg3), "BODY_LENGTH: %d != msg3: %d" % (self.EXPECTED_BODY_LENGTH, len(msg3))

        # Adding the payload data to the message
        msg3 += payload

        return msg3


def get_version(negotiate_flags):
    # Check the negotiate_flag version is set, if it is make sure the version info is added to the data
    if negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION:
        # TODO: Get the major and minor version of Windows instead of using default values
        product_major_version = struct.pack('<B', 5)
        product_minor_version = struct.pack('<B', 1)
        product_build = struct.pack('<H', 2600)
        version_reserved = b'\0' * 3
        ntlm_revision_current = struct.pack('<B', 15)
        version = product_major_version + product_minor_version + product_build + version_reserved + ntlm_revision_current
    else:
        version = b'\0' * 8

    return version