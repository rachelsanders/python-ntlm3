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
import binascii
import calendar
import hashlib
import hmac
import random
import re
import six
import struct
import time
from ntlm3.constants import NegotiateFlags
from ntlm3.gss_channel_bindings import GssChannelBindingsStruct
from ntlm3.target_info import TargetInfo
from . import des

class ComputeResponse():
    """
        Constructor for the response computations. This class will compute the various
        nt and lm challenge responses.

        :param domain: The domain name
        :param user_name: The username
        :param password: The password
        :param server_challenge: The server_challenge nonce from the CHALLENGE_MESSAGE
        :param server_target_info: The target_info value returned from the CHALLENGE_MESSAGE
        :param ntlm_compatibility: The NTLM Compatibility level to use with the message. See ntlm.py create_NTLM_AUTHENTICATE_MESSAGE() for more details
        :param client_challenge: The client_challenge nonce for the AUTHENTICATE_MESSAGE, will generate a random one if not supplied
    """
    def __init__(self, negotiate_flags, domain, user_name, password, server_challenge, server_target_info, ntlm_compatibility, client_challenge=None):
        self._negotiate_flags = negotiate_flags
        self._domain = domain.decode()
        self._user_name = user_name.decode()
        self._password = password
        self._server_challenge = server_challenge
        self._server_target_info = server_target_info

        # Check that the ntlm_compatibility level is set to a valid value
        if (ntlm_compatibility < 0) or (ntlm_compatibility > 5):
            raise Exception("Unknown ntlm_compatibility level - expecting value between 0 and 5")
        self._ntlm_compatibility = ntlm_compatibility

        # Generate a random client challenge if one isn't set
        if client_challenge is None:
            # Generate random 8 byte character for the client_challenge otherwise
            ran_client_challenge = b""
            for i in range(8):
                ran_client_challenge += six.int2byte(random.getrandbits(8))
            self._client_challenge = ran_client_challenge
        else:
            self._client_challenge = client_challenge



    """
        [MS-NLMP] v28.0 2016-07-14

        3.3.1 - NTLM v1 Authentication
        3.3.2 - NTLM v2 Authentication

        :return: nt_challenge_response (LmChallengeResponse) - The LM response to the server challenge. Computed by the client
        This method returns the LmChallengeResponse key based on the ntlm_compatibility chosen
        and the target_info supplied by the CHALLENGE_MESSAGE. It is quite different from what
        is set in the document as it combines the NTLM v1, NTLM2 and NTLM v2 methods into one
        and calls separate methods based on the ntlm_compatibility chosen.
    """
    def get_lm_challenge_response(self):
        if self._negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and self._ntlm_compatibility < 3:
            # The compatibility level is less than 3 which means it doesn't support NTLMv2 but we want extended security so use NTLM2 which is different from NTLMv2
            # [MS-NLMP] - 3.3.1 NTLMv1 Authentication
            response = b'\xaa' * 8 + b'\0' * 16

        elif 0 <= self._ntlm_compatibility <= 1:
            response = self._get_LMv1_response(self._password, self._server_challenge)
        elif self._ntlm_compatibility == 2:
            # Based on the compatibility level we don't want to use LM responses
            response = self._get_NTLMv1_response(self._password, self._server_challenge)
        else:
            # [MS-NLMP] - 3.3.2 NTLMv2 Authentication
            response = self._get_LMv2_response(self._domain, self._user_name, self._password, self._server_challenge, self._client_challenge)

        return response

    """
        [MS-NLMP] v28.0 2016-07-14

        3.3.1 - NTLM v1 Authentication
        3.3.2 - NTLM v2 Authentication

        :param server_certificate_hash: The SHA256 hash of the server certificate NTLM is authenticating to. This is used to add to the gss_channel_bindings_struct
                                        for Channel Binding Tokens. If none is passed through then python-ntlm3 will not use Channel Binding Tokens when authenticating
                                        with the server which could cause issues if it is set to only authenticate when these are present. This is only used for NTLMv2
                                        authentication.
        :return: nt_challenge_response (NTChallengeResponse) - The NT response to the server challenge.
                    Computed by the client
                 client_target_info (ServerName) - The AV_PAIR structure set in the NTChallengeResponse.

        This method returns the NTChallengeResponse key based on the ntlm_compatibility chosen
        and the target_info supplied by the CHALLENGE_MESSAGE. It is quite different from what
        is set in the document as it combines the NTLM v1, NTLM2 and NTLM v2 methods into one
        and calls separate methods based on the ntlm_compatibility chosen.
    """
    def get_nt_challenge_response(self, server_certificate_hash=None):
        # Create blank target_info variable in case it isn't NTLMv2
        target_info = None

        if self._negotiate_flags & NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and self._ntlm_compatibility < 3:
            # The compatibility level is less than 3 which means it doesn't support NTLMv2 but we want extended security so use NTLM2 which is different from NTLMv2
            # [MS-NLMP] - 3.3.1 NTLMv1 Authentication
            response = self._get_NTLM2_response(self._password, self._server_challenge, self._client_challenge)

        elif 0 <= self._ntlm_compatibility < 3:
            response = self._get_NTLMv1_response(self._password, self._server_challenge)
        else:
            # [MS-NLMP] - 3.3.2 NTLMv2 Authentication
            if self._server_target_info is None:
                target_info = TargetInfo()
            else:
                target_info = self._server_target_info

            if target_info[TargetInfo.MSV_AV_TIMESTAMP] is None:
                timestamp = self._get_windows_timestamp()
            else:
                timestamp = target_info[TargetInfo.MSV_AV_TIMESTAMP][1]
                # TODO: Need to calculate the MIC when this flag is present

            if server_certificate_hash != None:
                channel_bindings_hash = self._get_channel_bindings_value(server_certificate_hash)
                target_info[TargetInfo.MSV_AV_CHANNEL_BINDINGS] = channel_bindings_hash

            response = self._get_NTLMv2_response(self._domain, self._user_name, self._password, self._server_challenge, self._client_challenge, timestamp, target_info)

        return response, target_info


    """
        [MS-NLMP] v28.0 2016-07-14

        3.3.1 NTLM v1 Authentication
        Note: Same function as LMOWFv1 in document
    """
    def _lmowfv1(self, password):
        """create LanManager hashed password"""

        # if the password provided is already a hash, we just return the first half
        if re.match(r'^[\w]{32}:[\w]{32}$', password):
            return binascii.unhexlify(password.split(':')[0])

        # fix the password length to 14 bytes
        password = password.upper()
        lm_pw = password + '\0' * (14 - len(password))
        lm_pw = password[0:14]

        # do hash
        magic_str = b"KGS!@#$%"  # page 57 in [MS-NLMP]

        res = b''
        dobj = des.DES(lm_pw[0:7])
        res = res + dobj.encrypt(magic_str)

        dobj = des.DES(lm_pw[7:14])
        res = res + dobj.encrypt(magic_str)

        return res

    """
        [MS-NLMP] v28.0 2016-07-14

        3.3.1 NTLM v1 Authentication
        Note: Same function as NTOWFv1 in document
    """
    def _ntowfv1(self, password):
        "create NT hashed password"
        # if the password provided is already a hash, we just return the second half
        if re.match(r'^[\w]{32}:[\w]{32}$', password):
            return binascii.unhexlify(password.split(':')[1])

        digest = hashlib.new('md4', password.encode('utf-16le')).digest()
        return digest

    """
        [MS-NLMP] v28.0 2016-07-14

        3.3.2 NTLM v1 Authentication
        Note: Same function as LMOWFv2 and NTOWFv2 in document
    """
    def _ntowfv2(self, password, user_name, domain):
        "create NT hashed password"
        digest = self._ntowfv1(password)

        return hmac.new(digest, (user_name.upper() + domain).encode('utf-16le')).digest()

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.2.3 LM_RESPONSE
        The LM_RESPONSE structure defines the NTLM v1 authentication LmChallengeResponse
        in the AUTHENTICATE_MESSAGE. This response is used only when NTLM v1
        authentication is configured.
    """
    def _get_LMv1_response(self, password, server_challenge):
        lm_hash = self._lmowfv1(password)
        response = self._calc_resp(lm_hash, server_challenge)

        return response

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.2.4 LMv2_RESPONSE
        The LMv2_RESPONSE structure defines the NTLM v2 authentication LmChallengeResponse
        in the AUTHENTICATE_MESSAGE. This response is used only when NTLM v2
        authentication is configured.
    """
    def _get_LMv2_response(self, domain, user_name, password, server_challenge, client_challenge):
        nt_hash = self._ntowfv2(password, user_name, domain)
        lm_hash = hmac.new(nt_hash, (server_challenge + client_challenge)).digest()
        response = lm_hash + client_challenge

        return response

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.2.6 NTLM v1 Response: NTLM_RESPONSE
        The NTLM_RESPONSE strucutre defines the NTLM v1 authentication NtChallengeResponse
        in the AUTHENTICATE_MESSAGE. This response is only used when NTLM v1 authentication
        is configured.
    """
    def _get_NTLMv1_response(self, password, server_challenge):
        ntlm_hash = self._ntowfv1(password)
        response = self._calc_resp(ntlm_hash, server_challenge)

        return response

    """
        [MS-NLMP] v28.0 2016-07-14

        This name is really misleading as it isn't NTLM v2 authentication rather
        This authentication is only used when the ntlm_compatibility level is set
        to a value < 3 (No NTLMv2 auth) but the NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        flag is set in the negotiate flags section. The documentation for computing this
        value is on page 56 under section 3.3.1 NTLM v1 Authentication
    """
    def _get_NTLM2_response(self, password, server_challenge, client_challenge):
        ntlm_hash = self._ntowfv1(password)
        nt_session_hash = hashlib.md5(server_challenge + client_challenge).digest()[:8]
        response = self._calc_resp(ntlm_hash, nt_session_hash[0:8])

        return response

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.2.8 NTLM V2 Response: NTLMv2_RESPONSE
        The NTLMv2_RESPONSE strucutre defines the NTLMv2 authentication NtChallengeResponse
        in the AUTHENTICATE_MESSAGE. This response is used only when NTLMv2 authentication
        is configured.

        The guide on how this is computed is in 3.3.2 NTLM v2 Authentication.
    """
    def _get_NTLMv2_response(self, domain, user_name, password, server_challenge, client_challenge, timestamp, target_info):
        # Response field - 16 bytes
        nt_hash = self._ntowfv2(password, user_name, domain)
        temp = self._get_NTLMv2_temp(timestamp, client_challenge, target_info)
        nt_proof_str = hmac.new(nt_hash, (server_challenge + temp)).digest()

        return nt_proof_str + temp

    """
        [MS-NLMP] v28.0 2016-07-14

        2.2.2.7 NTLMv2_CLIENT_CHALLENGE - variable length
        The NTLMv2_CLIENT_CHALLENGE structure defines the client challenge in
        the AUTHENTICATE_MESSAGE. This strucutre is used only when NTLM v2
        authentication is configured and is transported in the NTLMv2_RESPONSE
        structure.

        The method to create this structure is defined in 3.3.2 NTLMv2 Authentication.
        In this method this variable is known as the temp value. The target_info variable
        corresponds to the ServerName variable used in that documentation. This is in
        reality a lot more than just the ServerName and contains the AV_PAIRS structure
        we need to transport with the message like Channel Binding tokens and others.
        By default this will be the target_info returned from the CHALLENGE_MESSAGE plus
        MSV_AV_CHANNEL_BINDINGS if specified otherwise it is a new target_info set with
        MSV_AV_TIMESTAMP to the current time.
    """
    def _get_NTLMv2_temp(self, timestamp, client_challenge, target_info):
        resp_type = b'\1'
        hi_resp_type = b'\1'
        reserved1 = b'\0' * 2
        reserved2 = b'\0' * 4
        reserved3 = b'\0' * 4
        reserved4 = b'\0' * 4  # This byte is not in the structure defined in 2.2.2.7 but is in the computation guide, works with it present

        temp = resp_type + hi_resp_type + reserved1 + \
               reserved2 + \
               timestamp + \
               client_challenge + \
               reserved3 + \
               target_info.get_data() + reserved4

        return temp

    """_calc_resp generates the LM response given a 16-byte password hash and the
        challenge from the Type-2 message.
        @param password_hash
            16-byte password hash
        @param server_challenge
            8-byte challenge from Type-2 message
        returns
            24-byte buffer to contain the LM response upon return
    """
    def _calc_resp(self, password_hash, server_challenge):

        # padding with zeros to make the hash 21 bytes long
        password_hash += b'\0' * (21 - len(password_hash))

        res = b''
        dobj = des.DES(password_hash[0:7])
        res = res + dobj.encrypt(server_challenge[0:8])

        dobj = des.DES(password_hash[7:14])
        res = res + dobj.encrypt(server_challenge[0:8])

        dobj = des.DES(password_hash[14:21])
        res = res + dobj.encrypt(server_challenge[0:8])
        return res

    """
        https://msdn.microsoft.com/en-us/library/windows/desktop/dd919963%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        https://blogs.msdn.microsoft.com/openspecification/2013/03/26/ntlm-and-channel-binding-hash-aka-extended-protection-for-authentication/

        Get's the MD5 hash of the gss_channel_bindings_struct to add to the AV_PAIR MSV_AV_CHANNEL_BINDINGS.
        This method takes in the SHA256 hash (Hash of the DER encoded certificate of the server we are connecting to)
        and add's it to the gss_channel_bindings_struct. It then gets the MD5 hash and converts this to a
        byte array in preparation of adding it to the AV_PAIR structure.
    """
    def _get_channel_bindings_value(self, server_certificate_hash):
        # Channel Binding Tokens support, used for NTLMv2
        # Decode the SHA256 certificate hash
        certificate_digest = base64.b16decode(server_certificate_hash)

        # Initialise the GssChannelBindingsStruct and add the certificate_digest to the application_data field
        gss_channel_bindings = GssChannelBindingsStruct()
        gss_channel_bindings[gss_channel_bindings.APPLICATION_DATA] = 'tls-server-end-point:'.encode() + certificate_digest

        # Get the gss_channel_bindings_struct and create an MD5 hash
        channel_bindings_struct_data = gss_channel_bindings.get_data()
        channel_bindings_hash = hashlib.md5(channel_bindings_struct_data).hexdigest()

        try:
            cbt_value = bytearray.fromhex(channel_bindings_hash)
        except TypeError:
            # Work-around for Python 2.6 bug
            cbt_value = bytearray.fromhex(unicode(channel_bindings_hash))
        return bytes(cbt_value)

    def _get_windows_timestamp(self):
        # Get Windows Date time, 100 nanoseconds since 1601-01-01 in a 64 bit structure
        timestamp = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))

        return timestamp