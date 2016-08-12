import unittest2 as unittest # for compatiblity with older version of python
import mock

from ..utils import HexToByte

from ntlm3.compute_response import ComputeResponse
from ntlm3.target_info import TargetInfo
from ntlm3.constants import NegotiateFlags
from ntlm3.messages import ChallengeMessage

# Test values set by the Microsoft document, these shouldn't be changed
user_name = 'User'.encode('ascii')
password = 'Password'
domain_name = 'Domain'.encode('ascii')
server_challenge = HexToByte('01 23 45 67 89 ab cd ef')
client_challenge = HexToByte('aa aa aa aa aa aa aa aa')
timestamp = HexToByte('00 00 00 00 00 00 00 00')

# Test AV_PAIR structure used for NTLMv2 Calculaltions
target_info = TargetInfo()
target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = HexToByte('44 00 6f 00 6d 00 61 00 69 00 6e 00')
target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')

# Challenge Message example 4.2.4.3 used to attach to ComputeResponse as an example
challenge_message_hex = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                  '38 00 00 00 33 82 0a 82 01 23 45 67 89 ab cd ef'
                                  '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                  '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                  '65 00 72 00 00 00 00 00')
challenge_message = ChallengeMessage(challenge_message_hex)

# Generic compute_response to use for the Test_HashResults
compute_response = ComputeResponse(user_name, password, domain_name, challenge_message, 3)

# Used in the client challenge, we want to return hex aa for the length as per Microsoft's example
def mock_random(ignore):
    hex_value = 0xaa
    return hex_value

def mock_timestamp():
    return timestamp

"""
    [MS-NLMP] v28.0 2016-07-14

    4.2 Cryptographic Values for Validation
    The following tests use known inputs in the documentation and tests
    the outputs for various compute functions set out by Microsoft.
    Please do not modify the expected results unless it is otherwise specified
    as they will validate the functions work correctly.

    The corresponding exmaples are set in the comments before the function
"""
class Test_HashResults(unittest.TestCase):
    # 4.2.2.1.1 - LMOWFv1()
    def test_lmowfv1(self):
        expected = HexToByte('e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d')
        actual = compute_response._lmowfv1(password)

        assert actual == expected

    # 4.2.2.1.2 - NTOWFv1()
    def test_ntowfv1(self):
        expected = HexToByte('a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52')
        actual = compute_response._ntowfv1(password)

        assert actual == expected

    # 4.2.4.1.1 - NTOWFv2() and LMOWFv2()
    def test_ntowfv2(self):
        expected = HexToByte('0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f')
        actual = compute_response._ntowfv2(user_name.decode(), password, domain_name.decode())

        assert actual == expected

    # 4.2.2.2.2 - LMv1 Response
    def test_get_LMv1_response(self):
        expected = HexToByte('98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72'
                             'de f1 1c 7d 5c cd ef 13')
        actual = compute_response._get_LMv1_response(password, server_challenge)

        assert actual == expected

    # 4.2.4.2.1 - LMv2 Response
    def test_get_LMv2_response(self):
        expected = HexToByte('86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19'
                             'aa aa aa aa aa aa aa aa')
        actual = compute_response._get_LMv2_response(user_name.decode(), password, domain_name.decode(), server_challenge, client_challenge)

        assert actual == expected

    # 4.2.2.2.1 - NTLMv1 Response
    def test_get_NTLMv1_response(self):
        expected = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                             '44 bd be d9 27 84 1f 94')
        actual = compute_response._get_NTLMv1_response(password, server_challenge)

        assert actual == expected

    # 4.2.3.2.2 - NTLMv1 Response
    def test_get_NTLM2_response(self):
        expected = HexToByte('75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8'
                             '1e 97 ed 26 83 26 72 32')
        actual = compute_response._get_NTLM2_response(password, server_challenge, client_challenge)

        assert actual == expected

    # 4.2.4.1.3 - temp
    def test_nt_v2_temp_response(self):
        expected = HexToByte('01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                             'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                             '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                             '53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00'
                             '00 00 00 00')
        actual = compute_response._get_NTLMv2_temp(timestamp, client_challenge, target_info)
        assert actual == expected

    # 4.2.4.2.2 - NTLMv2 Response
    # In this example it is only returning the nt_proof_str, our method returns more than this but will verify the example given in the first line of expected
    def test_get_NTLMv2_response(self):
        expected = HexToByte('68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c' # This is the MS example, corresponds to the nt_proof_str in our method
                             '01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00' # This (and lines below) is the temp value added, corresponds to 4.2.4.1.3 - temp
                             'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                             '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                             '53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00'
                             '00 00 00 00')
        actual = compute_response._get_NTLMv2_response(user_name.decode(), password, domain_name.decode(),
                                                       server_challenge, client_challenge, timestamp, target_info)

        assert actual == expected

    # No example is explicitly set in MS-NLMP, using a random certificate hash and checking with the expected outcome
    def test_channel_bindings_value(self):
        expected = HexToByte('6E A1 9D F0 66 DA 46 22 05 1F 9C 4F 92 C6 DF 74')
        actual = compute_response._get_channel_bindings_value('E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405')

        assert actual == expected

# Really are the same tests as above with the same expected results but this tests the logic of the lm and nt response method instead of the computation itself
class Test_ChallengeResults(unittest.TestCase):
    def test_lm_v1_response(self):
        expected = HexToByte('98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72'
                             'de f1 1c 7d 5c cd ef 13')
        test_challenge_message = challenge_message
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 1).get_lm_challenge_response()

        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_lm_v1_with_extended_security_response(self, random_function):
        expected = HexToByte('aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00'
                             '00 00 00 00 00 00 00 00')
        test_challenge_message = challenge_message
        test_challenge_message.negotiate_flags += NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 1).get_lm_challenge_response()

        assert actual == expected

    def test_lm_v1_with_ntlm_2_response(self):
        expected = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                             '44 bd be d9 27 84 1f 94')
        test_challenge_message = challenge_message
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 2).get_lm_challenge_response()

        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_lm_v2_response(self, random_function):
        expected = HexToByte('86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19'
                             'aa aa aa aa aa aa aa aa')
        test_challenge_message = challenge_message
        test_challenge_message.negotiate_flags += NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 3).get_lm_challenge_response()

        assert actual == expected

    def test_nt_v1_response(self):
        expected = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                             '44 bd be d9 27 84 1f 94')
        test_challenge_message = challenge_message
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 1).get_nt_challenge_response(None)

        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_nt_v1_with_extended_security_response(self, random_function):
        expected = HexToByte('75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8'
                             '1e 97 ed 26 83 26 72 32')
        test_challenge_message = challenge_message
        test_challenge_message.negotiate_flags += NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 1).get_nt_challenge_response(None)

        assert actual == expected

    @mock.patch('random.getrandbits', side_effect=mock_random)
    @mock.patch('ntlm3.compute_response.ComputeResponse._get_windows_timestamp', side_effect=mock_timestamp)
    def test_nt_v2_response(self, random_function, timestamp_function):
        expected = HexToByte('68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c'
                             '01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                             'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                             '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                             '53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00'
                             '00 00 00 00')

        test_challenge_message = challenge_message
        test_challenge_message.target_info = target_info
        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 3).get_nt_challenge_response(None)

        assert actual == expected

    # This test is different from the other Microsoft examples, they don't have an example where the AV_TIMESTAMP pair is present, using our own expected results
    @mock.patch('random.getrandbits', side_effect=mock_random)
    def test_nt_v2_response_with_timestamp_av_pair(self, random_function):
        test_target_info = target_info
        test_target_info[TargetInfo.MSV_AV_TIMESTAMP] = timestamp
        expected = HexToByte('fb 4e c5 8d 66 2a 1e bc 3b 55 24 97 1d 77 20 7e'
                             '01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                             'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                             '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                             '53 00 65 00 72 00 76 00 65 00 72 00 07 00 08 00'
                             '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        test_challenge_message = challenge_message
        test_challenge_message.target_info = test_target_info

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 3).get_nt_challenge_response(None)

        assert actual == expected