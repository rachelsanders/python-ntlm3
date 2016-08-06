import unittest
import mock

from ntlm3 import ntlm
from ntlm3.constants import NegotiateFlags

from ..utils import HexToByte

user_name = 'User'
domain = 'Domain'
password = 'Password'
workstation = 'COMPUTER'

def mock_gethostname():
    return workstation

# Used in the client challenge, we want to return hex aa for the length as per Microsoft's example
def mock_random(ignore):
    hex_value = 0xaa
    return hex_value

def mock_timestamp(ignore):
    return 1470454519 # Return 1 date for all tests

# Running a test that uses the same flags as the HTTPNtlmAuthHandler to ensure consistency
# Need a way to use the Microsoft examples as well but until the full protocal has been added, there isn't much we can do
class Test_MessageResponsesNTLMv1(unittest.TestCase):

    @mock.patch('socket.gethostname', side_effect=mock_gethostname)
    def test_negotiate_message_v1(self, gethostname_function):
        expected = 'TlRMTVNTUAABAAAABjIIAgQABAAoAAAACAAIACwAAAAFASgKAAAAD1VTRVJDT01QVVRFUg=='
        actual = ntlm.create_NTLM_NEGOTIATE_MESSAGE(user_name)

        assert actual == expected

    def test_challenge_parsing_v1(self):
        expected_challenge = HexToByte('de 4e ca 47 1f 87 19 84')
        expected_flags = 2726920709L
        expected_target_info = HexToByte('02 00 04 00 4e 00 41 00 01 00 16 00 4e 00 41 00 53 00 41 '
                                         '00 4e 00 45 00 58 00 48 00 43 00 30 00 34 00 04 00 1e 00 '
                                         '6e 00 61 00 2e 00 71 00 75 00 61 00 6c 00 63 00 6f 00 6d '
                                         '00 6d 00 2e 00 63 00 6f 00 6d 00 03 00 36 00 6e 00 61 00 '
                                         '73 00 61 00 6e 00 65 00 78 00 68 00 63 00 30 00 34 00 2e '
                                         '00 6e 00 61 00 2e 00 71 00 75 00 61 00 6c 00 63 00 6f 00 '
                                         '6d 00 6d 00 2e 00 63 00 6f 00 6d 00 05 00 22 00 63 00 6f '
                                         '00 72 00 70 00 2e 00 71 00 75 00 61 00 6c 00 63 00 6f 00 '
                                         '6d 00 6d 00 2e 00 63 00 6f 00 6d 00 07 00 08 00 0d 71 e8 '
                                         'b8 d2 e3 cc 01 00 00 00 00')

        (actual_challenge, actual_flags, actual_target_info) = ntlm.parse_NTLM_CHALLENGE_MESSAGE(
            'TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABY'
            'ATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAG'
            'UAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtA'
            'G0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA')

        assert actual_challenge == expected_challenge
        assert actual_flags == expected_flags
        assert actual_target_info.get_data() == expected_target_info

    @mock.patch('socket.gethostname', side_effect=mock_gethostname)
    def test_authenticate_message_nlmt_v1(self, gethostname_function):
        server_challenge = HexToByte('de 4e ca 47 1f 87 19 84')
        server_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                    NegotiateFlags.NTLMSSP_REQUEST_TARGET |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION)

        expected = 'TlRMTVNTUAADAAAAGAAYAEgAAAAYABgAYAAAAAwADAB4AAAACAAIAIQAAAAQABAAjAAAAAAAAACcAAAABQKIAgUBKAo' \
                   'AAAAPIqDBlPYuak8LHYGlrGPUhD18/p8e7g840E/uo8aaDG9pSchiBEHaCfb3dJMshfFuRABPAE0AQQBJAE4AVQBzAG' \
                   'UAcgBDAE8ATQBQAFUAVABFAFIA'
        actual = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, user_name, domain, password, server_flags, ntlm_compatibility=1)

        assert actual == expected

    @mock.patch('socket.gethostname', side_effect=mock_gethostname)
    def test_authenticate_message_nlmt_v1_non_unicode(self, gethostname_function):
        server_challenge = HexToByte('de 4e ca 47 1f 87 19 84')
        server_flags = (NegotiateFlags.NTLMSSP_REQUEST_TARGET |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                    NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION)

        expected = 'TlRMTVNTUAADAAAAGAAYAEgAAAAYABgAYAAAAAYABgB4AAAABAAEAH4AAAAIAAgAggAAAAAAAACKAAAABQKIAgUBKA' \
                   'oAAAAPIqDBlPYuak8LHYGlrGPUhD18/p8e7g840E/uo8aaDG9pSchiBEHaCfb3dJMshfFuRE9NQUlOVXNlckNPTVBVVEVS'
        actual = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, user_name, domain, password, server_flags, ntlm_compatibility=1)

        assert actual == expected

    @mock.patch('socket.gethostname', side_effect=mock_gethostname)
    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_authenticate_message_ntlm_v1_with_extended_security(self, gethostname_function, random_function):
        server_challenge = HexToByte('de 4e ca 47 1f 87 19 84')
        server_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                        NegotiateFlags.NTLMSSP_REQUEST_TARGET |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION)

        expected = 'TlRMTVNTUAADAAAAGAAYAEgAAAAYABgAYAAAAAwADAB4AAAACAAIAIQAAAAQABAAjAAAAAAAAACcAAAABQKIAgUBKAo' \
                   'AAAAPqqqqqqqqqqoAAAAAAAAAAAAAAAAAAAAAwH67efBbtIQ50bY/V0zkP2Np99sPVnwTRABPAE0AQQBJAE4AVQBzAG' \
                   'UAcgBDAE8ATQBQAFUAVABFAFIA'
        actual = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, user_name, domain, password, server_flags, ntlm_compatibility=1)

        assert actual == expected

    @mock.patch('socket.gethostname', side_effect=mock_gethostname)
    @mock.patch('random.getrandbits', side_effect=mock_random)
    @mock.patch('calendar.timegm', side_effect=mock_timestamp)
    def test_authenticate_message_ntlm_v3(self, gethostname_function, random_function, timestamp_function):
        server_challenge = HexToByte('de 4e ca 47 1f 87 19 84')
        server_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE |
                        NegotiateFlags.NTLMSSP_REQUEST_TARGET |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO |
                        NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION)

        expected = 'TlRMTVNTUAADAAAAGAAYAEgAAAA0ADQAYAAAAAwADACUAAAACAAIAKAAAAAQABAAqAAAAAAAAAC4AAAABQKIAgUBKAo' \
                   'AAAAPfPVrhszfU03N3Mizf0vlf6qqqqqqqqqqOCIgDVuzKGw0x7s4X4/0HwEBAAAAAAAAgLXgjZPv0QGqqqqqqqqqqg' \
                   'AAAAAAAAAAAAAAAEQATwBNAEEASQBOAFUAcwBlAHIAQwBPAE0AUABVAFQARQBSAA=='
        actual = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(server_challenge, user_name, domain, password, server_flags,
                                                       ntlm_compatibility=3)
        print actual

        assert actual == expected