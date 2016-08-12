import unittest2 as unittest # for compatiblity with older version of python
import mock
import struct

from ..utils import HexToByte

from ntlm3.constants import NegotiateFlags, MessageTypes, NTLM_SIGNATURE
from ntlm3.messages import NegotiateMessage, ChallengeMessage, AuthenticateMessage
from ntlm3.target_info import TargetInfo

user_name = 'User'
password = 'Password'
domain_name = 'Domain'
workstation = 'COMPUTER'

negotiate_flags = (NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_56 |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_128 |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION |
                   NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_OEM |
                   NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE)

challenge_message_v1 = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                 '38 00 00 00 33 82 0a 82 01 23 45 67 89 ab cd ef'
                                 '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                 '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                 '65 00 72 00 00 00 00 00')

challenge_message_v2 = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                 '38 00 00 00 37 82 8a e2 01 23 45 67 89 ab cd ef'
                                 '00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00'
                                 '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                 '65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00'
                                 '69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00'
                                 '65 00 72 00 00 00 00 00')

# Used in the client challenge, we want to return hex aa for the length as per Microsoft's example
def mock_random(ignore):
    hex_value = 0xaa
    return hex_value

def mock_timestamp(ignore):
    return 1470454519 # Return 1 date for all tests

class Test_Negotiate(unittest.TestCase):
    def test_negotiate_with_all(self):
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 01 00 00 00 32 b2 02 e2'
                             '06 00 06 00 28 00 00 00 08 00 08 00 2e 00 00 00'
                             '05 01 28 0a 00 00 00 0f 44 6f 6d 61 69 6e 43 4f'
                             '4d 50 55 54 45 52')
        test_flags = negotiate_flags
        actual = NegotiateMessage(test_flags, domain_name, workstation).get_data()
        assert actual == expected

    def test_negotiate_without_version(self):
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 01 00 00 00 32 b2 02 e0'
                             '06 00 06 00 28 00 00 00 08 00 08 00 2e 00 00 00'
                             '00 00 00 00 00 00 00 00 44 6f 6d 61 69 6e 43 4f'
                             '4d 50 55 54 45 52')
        test_flags = negotiate_flags
        test_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
        actual = NegotiateMessage(test_flags, domain_name, workstation).get_data()
        assert actual == expected

    def test_negotiate_without_domain_workstation(self):
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 01 00 00 00 32 82 02 e2'
                             '00 00 00 00 28 00 00 00 00 00 00 00 28 00 00 00'
                             '05 01 28 0a 00 00 00 0f')
        test_flags = negotiate_flags
        actual = NegotiateMessage(test_flags, None, None).get_data()
        assert actual == expected

class Test_Challenge(unittest.TestCase):

    def test_challenge(self):
        # This is the challenge message from Microsoft 4.2.2.3, no target_info and target_name
        actual = ChallengeMessage(challenge_message_v1)

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


    def test_challenge_no_version(self):
        # Same as test_challenge but the neg_flags have removed the version and version info has been zerod
        test_challenge_message = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                           '38 00 00 00 33 82 0a 80 01 23 45 67 89 ab cd ef'
                                           '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                           '00 00 00 00 00 00 00 00 53 00 65 00 72 00 76 00'
                                           '65 00 72 00 00 00 00 00')
        actual = ChallengeMessage(test_challenge_message)

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 2148172339
        expected_server_challenge = HexToByte('01 23 45 67 89 ab cd ef')
        expected_signature = NTLM_SIGNATURE
        expected_target_info = None
        expected_target_name = None
        expected_version = None

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

    def test_challenge_with_target_info(self):
        # This is the challenge message from Microsoft 4.2.4.3, neg_flags modified so the target_name is actually returned
        test_target_info = TargetInfo()
        test_target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = HexToByte('44 00 6f 00 6d 00 61 00 69 00 6e 00')
        test_target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')
        actual = ChallengeMessage(challenge_message_v2)

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 3800728119
        expected_server_challenge = HexToByte('01 23 45 67 89 ab cd ef')
        expected_signature = NTLM_SIGNATURE
        expected_target_info = test_target_info.get_data()
        expected_target_name = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')
        expected_version = struct.unpack("<q", HexToByte('06 00 70 17 00 00 00 0f'))[0]

        actual_message_type = actual.message_type
        actual_negotiate_flags = actual.negotiate_flags
        actual_server_challenge = actual.server_challenge
        actual_signature = actual.signature
        actual_target_info = actual.target_info.get_data()
        actual_target_name = actual.target_name
        actual_version = actual.version

        assert actual_message_type == expected_message_type
        assert actual_negotiate_flags == expected_negotiate_flags
        assert actual_server_challenge == expected_server_challenge
        assert actual_signature == expected_signature
        assert actual_target_info == expected_target_info
        assert actual_target_name == expected_target_name
        assert actual_version == expected_version

class Test_Authenticate(unittest.TestCase):
    # Cannot use the Microsoft examples for now as we don't support MIC and session keys, TODO: Change test when this is supported

    def test_authenticate_message_ntlm_v1(self):
        test_challenge_message = ChallengeMessage(challenge_message_v1)
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '48 00 00 00 18 00 18 00 60 00 00 00 0c 00 0c 00'
                             '78 00 00 00 08 00 08 00 84 00 00 00 10 00 10 00'
                             '8c 00 00 00 00 00 00 00 9c 00 00 00 33 82 02 82'
                             '05 01 28 0a 00 00 00 0f 98 de f7 b8 7f 88 aa 5d'
                             'af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13'
                             '67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                             '44 bd be d9 27 84 1f 94 44 00 4f 00 4d 00 41 00'
                             '49 00 4e 00 55 00 73 00 65 00 72 00 43 00 4f 00'
                             '4d 00 50 00 55 00 54 00 45 00 52 00')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation, test_challenge_message, 1, None).get_data()
        assert actual == expected

    def test_authenticate_without_domain_workstation(self):
        test_challenge_message = ChallengeMessage(challenge_message_v1)
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '48 00 00 00 18 00 18 00 60 00 00 00 00 00 00 00'
                             '78 00 00 00 08 00 08 00 78 00 00 00 00 00 00 00'
                             '80 00 00 00 00 00 00 00 80 00 00 00 33 82 02 82'
                             '05 01 28 0a 00 00 00 0f 98 de f7 b8 7f 88 aa 5d'
                             'af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13'
                             '67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                             '44 bd be d9 27 84 1f 94 55 00 73 00 65 00 72 00')
        actual = AuthenticateMessage(user_name, password, None, None, test_challenge_message, 1, None).get_data()
        assert actual == expected

    def test_authenticate_message_ntlm_v1_non_unicode(self):
        test_challenge_message = ChallengeMessage(challenge_message_v1)
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE
        test_challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '48 00 00 00 18 00 18 00 60 00 00 00 06 00 06 00'
                             '78 00 00 00 04 00 04 00 7e 00 00 00 08 00 08 00'
                             '82 00 00 00 00 00 00 00 8a 00 00 00 32 82 02 82'
                             '05 01 28 0a 00 00 00 0f 98 de f7 b8 7f 88 aa 5d'
                             'af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13'
                             '67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                             '44 bd be d9 27 84 1f 94 44 4f 4d 41 49 4e 55 73'
                             '65 72 43 4f 4d 50 55 54 45 52')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation, test_challenge_message, 1, None).get_data()
        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_authenticate_message_ntlm_v1_with_extended_security(self, random_function):
        test_challenge_message = ChallengeMessage(challenge_message_v1)
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '48 00 00 00 18 00 18 00 60 00 00 00 0c 00 0c 00'
                             '78 00 00 00 08 00 08 00 84 00 00 00 10 00 10 00'
                             '8c 00 00 00 00 00 00 00 9c 00 00 00 33 82 0a 82'
                             '05 01 28 0a 00 00 00 0f aa aa aa aa aa aa aa aa'
                             '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                             '75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8'
                             '1e 97 ed 26 83 26 72 32 44 00 4f 00 4d 00 41 00'
                             '49 00 4e 00 55 00 73 00 65 00 72 00 43 00 4f 00'
                             '4d 00 50 00 55 00 54 00 45 00 52 00')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation, test_challenge_message, 1,
                                     None).get_data()
        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    @mock.patch('calendar.timegm', side_effect=mock_timestamp)
    def test_authenticate_message_ntlm_v2(self, random_function, timestamp_function):
        test_challenge_message = ChallengeMessage(challenge_message_v2)
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '48 00 00 00 54 00 54 00 60 00 00 00 0c 00 0c 00'
                             'b4 00 00 00 08 00 08 00 c0 00 00 00 10 00 10 00'
                             'c8 00 00 00 00 00 00 00 d8 00 00 00 37 82 8a e2'
                             '05 01 28 0a 00 00 00 0f 4b aa f8 28 25 fe 69 eb'
                             '32 4e 4b 03 ad e1 16 69 aa aa aa aa aa aa aa aa'
                             '53 1e 9d 7b 8d 6f 3d 22 64 a2 43 95 ce 58 47 d9'
                             '01 01 00 00 00 00 00 00 80 b5 e0 8d 93 ef d1 01'
                             'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                             '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                             '53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00'
                             '00 00 00 00 44 00 4f 00 4d 00 41 00 49 00 4e 00'
                             '55 00 73 00 65 00 72 00 43 00 4f 00 4d 00 50 00'
                             '55 00 54 00 45 00 52 00')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation, test_challenge_message, 3,
                                     None).get_data()
        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    @mock.patch('calendar.timegm', side_effect=mock_timestamp)
    def test_authenticate_message_with_cbt(self, random_function, timestamp_function):
        test_challenge_message = ChallengeMessage(challenge_message_v2)
        test_server_cert_hash = 'E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405'
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '48 00 00 00 68 00 68 00 60 00 00 00 0c 00 0c 00'
                             'c8 00 00 00 08 00 08 00 d4 00 00 00 10 00 10 00'
                             'dc 00 00 00 00 00 00 00 ec 00 00 00 37 82 8a e2'
                             '05 01 28 0a 00 00 00 0f 4b aa f8 28 25 fe 69 eb'
                             '32 4e 4b 03 ad e1 16 69 aa aa aa aa aa aa aa aa'
                             '9d 6d 3a 72 0a 9b d1 c8 da 33 76 26 99 b3 b8 63'
                             '01 01 00 00 00 00 00 00 80 b5 e0 8d 93 ef d1 01'
                             'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                             '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                             '53 00 65 00 72 00 76 00 65 00 72 00 0a 00 10 00'
                             '6e a1 9d f0 66 da 46 22 05 1f 9c 4f 92 c6 df 74'
                             '00 00 00 00 00 00 00 00 44 00 4f 00 4d 00 41 00'
                             '49 00 4e 00 55 00 73 00 65 00 72 00 43 00 4f 00'
                             '4d 00 50 00 55 00 54 00 45 00 52 00')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation, test_challenge_message, 3,
                                     test_server_cert_hash).get_data()
        assert actual == expected
