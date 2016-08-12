import unittest2 as unittest
import mock
import struct

from ntlm3.ntlm import Ntlm
from ntlm3.constants import NegotiateFlags, MessageTypes, NTLM_SIGNATURE

from ..utils import HexToByte

user_name = 'User'
password = 'Password'
domain_name = 'Domain'
workstation = 'COMPUTER'

default_ntlm_context = Ntlm(ntlm_compatibility=0)
default_ntlm_compatibility = 3
default_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                 NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                 NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
default_challenge_string = 'TlRMTVNTUAACAAAADAAMADgAAAAzggqCASNFZ4mrze8AAAAAAAAAAAAAAAAAAAAABgBwFwAAAA9TAGUAcgB2AGUAcg=='

# Used in the client challenge, we want to return hex aa for the length as per Microsoft's example
def mock_random(ignore):
    hex_value = 0xaa
    return hex_value

# Running a test that uses the same flags as the HTTPNtlmAuthHandler to ensure consistency
# Need a way to use the Microsoft examples as well but until the full protocol has been added, there isn't much we can do
class Test_InitialiseNtlm(unittest.TestCase):

    def test_initialise_defaults(self):
        ntlm_context = Ntlm()
        expected_flags = default_flags
        expected_ntlm_compatibility = default_ntlm_compatibility

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm0(self):
        ntlm_context = Ntlm(ntlm_compatibility=0)
        expected_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                          NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                          NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                          NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY)
        expected_ntlm_compatibility = 0

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm1(self):
        ntlm_context = Ntlm(ntlm_compatibility=1)
        expected_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                          NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                          NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                          NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        expected_ntlm_compatibility = 1

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm2(self):
        ntlm_context = Ntlm(ntlm_compatibility=2)
        expected_flags = default_flags
        expected_ntlm_compatibility = 2

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm3(self):
        ntlm_context = Ntlm(ntlm_compatibility=3)
        expected_flags = default_flags
        expected_ntlm_compatibility = 3

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm4(self):
        ntlm_context = Ntlm(ntlm_compatibility=4)
        expected_flags = default_flags
        expected_ntlm_compatibility = 4

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm5(self):
        ntlm_context = Ntlm(ntlm_compatibility=5)
        expected_flags = default_flags
        expected_ntlm_compatibility = 5

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_illegal_ntlm_compatibility_high(self):
        with self.assertRaises(Exception) as context:
            Ntlm(ntlm_compatibility=6)

        self.assertTrue('Unknown ntlm_compatibility level - expecting value between 0 and 5' in context.exception.args)

    def test_initialise_with_illegal_ntlm_compatibility_low(self):
        with self.assertRaises(Exception) as context:
            Ntlm(ntlm_compatibility=-1)

        self.assertTrue('Unknown ntlm_compatibility level - expecting value between 0 and 5' in context.exception.args)

    def test_initialise_with_session_security(self):
        ntlm_context = Ntlm(session_security='none')
        expected_flags = default_flags
        expected_ntlm_compatibility = default_ntlm_compatibility

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_illegal_session_security(self):
        with self.assertRaises(Exception) as context:
            Ntlm(session_security='not_allowed')

        self.assertTrue('session_security must be \'none\'' in context.exception.args)

    def test_initialise_oem_encoding(self):
        ntlm_context = Ntlm(use_oem_encoding=True)
        expected_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_OEM |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        expected_ntlm_compatibility = default_ntlm_compatibility

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_unicode_encoding(self):
        ntlm_context = Ntlm(use_oem_encoding=False)
        expected_flags = default_flags
        expected_ntlm_compatibility = default_ntlm_compatibility

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_without_version_debug(self):
        ntlm_context = Ntlm(use_version_debug=False)
        expected_flags = default_flags
        expected_ntlm_compatibility = default_ntlm_compatibility

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_version_debug(self):
        ntlm_context = Ntlm(use_version_debug=True)
        expected_flags = default_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
        expected_ntlm_compatibility = default_ntlm_compatibility

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

class Test_Messages(object):
    # Contains only lightweight tests, the actual message tests and its permutations are in test_message.py

    def test_create_negotiate_message(self):
        ntlm_context = default_ntlm_context
        expected = 'TlRMTVNTUAABAAAAgjKAAAYABgAoAAAACAAIAC4AAAAAAAAAAAAAAERvbWFpbkNPTVBVVEVS'
        actual = ntlm_context.create_negotiate_message(domain_name, workstation).decode()

        assert actual == expected

    def test_parse_challenge_message(self):
        ntlm_context = default_ntlm_context
        ntlm_context.parse_challenge_message(default_challenge_string)
        actual = ntlm_context.challenge_message

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 2181726771
        expected_server_challenge = HexToByte('01 23 45 67 89 ab cd ef')
        expected_signature = NTLM_SIGNATURE
        expected_target_info = None
        expected_target_name = None
        expected_version = struct.unpack("<q", HexToByte('06 00 70 17 00 00 00 0f'))[0]

        actual_message_type = actual.message_type
        actual_negotiate_flags = actual.negotiate_flags
        actual_server_challenge = actual.server_challenge
        actual_signature = actual.signature
        actual_target_info = actual.target_info
        actual_target_name = actual.target_name
        actual_version = actual.version

        assert actual_message_type == expected_message_type
        assert actual_negotiate_flags == expected_negotiate_flags
        assert actual_server_challenge == expected_server_challenge
        assert actual_signature == expected_signature
        assert actual_target_info == expected_target_info
        assert actual_target_name == expected_target_name
        assert actual_version == expected_version

    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_create_authenticate_message(self, random_function):
        ntlm_context = default_ntlm_context
        ntlm_context.parse_challenge_message(default_challenge_string)

        expected = 'TlRMTVNTUAADAAAAGAAYAEgAAAAYABgAYAAAAAwADAB4AAAACAAIAIQAAAAQABAAjAAAAAAAAACcAAAAM4IKggUBKAo' \
                   'AAAAPqqqqqqqqqqoAAAAAAAAAAAAAAAAAAAAAdTf4A642cSjKRYIEvefK+B6X7SaDJnIyRABPAE0AQQBJAE4AVQBzAG' \
                   'UAcgBDAE8ATQBQAFUAVABFAFIA'
        actual = ntlm_context.create_authenticate_message(user_name, password, domain_name, workstation).decode()

        assert actual == expected