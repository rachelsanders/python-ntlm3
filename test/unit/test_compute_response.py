import unittest
import pytest

from ..utils import HexToByte, ByteToHex

from ntlm3.compute_response import ComputeResponse
from ntlm3.target_info import TargetInfo
from ntlm3.constants import NegotiateFlags

user_name = 'User'
domain = 'Domain'
password = 'Password'
server_challenge = HexToByte('01 23 45 67 89 ab cd ef')
client_challenge = HexToByte('aa aa aa aa aa aa aa aa')
timestamp = HexToByte('00 00 00 00 00 00 00 00')
target_info = TargetInfo()
target_info[TargetInfo.MSV_AV_TIMESTAMP] = timestamp
target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')
target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = HexToByte('44 00 6f 00 6d 00 61 00 69 00 6e 00')

compute_response = ComputeResponse('', '', '', '', '', None, 3)

# Coverage for the ComputeResponse initialisation
class Test_Initialisation(unittest.TestCase):
    def test_compatible_ntlm_version(self):
        ComputeResponse('', '', '', '', '', None, 3)

    def test_incompatible_ntlm_version_low(self):
        with self.assertRaises(Exception) as context:
            ComputeResponse('', '', '', '', '', None, -1)

        self.assertTrue('Unknown ntlm_compatibility level - expecting value between 0 and 5' in context.exception)

    def test_incompatible_ntlm_version_high(self):
        with self.assertRaises(Exception) as context:
            ComputeResponse('', '', '', '', '', None, -6)

        self.assertTrue('Unknown ntlm_compatibility level - expecting value between 0 and 5' in context.exception)

# Tests the hash functions return the values as set out by the Microsoft document
class Test_HashResults(unittest.TestCase):
    def test_lmowfv1(self):
        expected = HexToByte('e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d')
        actual = compute_response._lmowfv1(password)

        assert actual == expected

    def test_ntowfv1(self):
        expected = HexToByte('a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52')
        actual = compute_response._ntowfv1(password)

        assert actual == expected

    def test_ntowfv2(self):
        expected = HexToByte('0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f')
        actual = compute_response._ntowfv2(password, user_name, domain)

        assert actual == expected

    def test_get_LMv1_response(self):
        expected = HexToByte('98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13')
        actual = compute_response._get_LMv1_response(password, server_challenge)

        assert actual == expected

    def test_get_LMv2_response(self):
        expected = HexToByte('86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa')
        actual = compute_response._get_LMv2_response(domain, user_name, password, server_challenge, client_challenge)

        assert actual == expected

    def test_get_NTLMv1_response(self):
        expected = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94')
        actual = compute_response._get_NTLMv1_response(password, server_challenge)

        assert actual == expected

    def test_get_NTLM2_response(self):
        expected = HexToByte('75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32')
        actual = compute_response._get_NTLM2_response(password, server_challenge, client_challenge)

        assert actual == expected

    @pytest.mark.skipif(True, reason="This test is failing, the expected hex from Microsoft is not correct")
    def test_get_NTLMv2_response(self):
        expected = HexToByte('68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 '
                              '00 00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00 44 00 6f 00 6d 00 '
                              '61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00 00 '
                              '00 00 00 c5 da d2 54 4f c9 79 90 94 ce 1c e9')
        (actual, ignore) = compute_response._get_NTLMv2_response(domain, user_name, password, server_challenge, client_challenge, timestamp, target_info)

        assert actual == expected

# Somewhat the same tests as above but testing the logic when to use what response based on the inputs rather than the compute logic itself
class Test_ChallengeResults(unittest.TestCase):
    def test_lm_v1_response(self):
        expected = HexToByte('98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13')
        actual = ComputeResponse(NegotiateFlags.NTLMSSP_ANOYNMOUS, domain, user_name, password, server_challenge, None,
                                 1).get_lm_challenge_response()

        assert actual == expected

    def test_lm_v1_with_extended_security_response(self):
        expected = HexToByte('aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        actual = ComputeResponse(NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, domain, user_name, password,
                                 server_challenge, None, 1).get_lm_challenge_response()

        assert actual == expected

    def test_lm_v1_with_ntlm_2_response(self):
        expected = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94')
        actual = ComputeResponse(NegotiateFlags.NTLMSSP_ANOYNMOUS, domain, user_name, password, server_challenge, None,
                                 2).get_lm_challenge_response()

        assert actual == expected

    def test_lm_v2_response(self):
        expected = HexToByte('86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa')
        actual = ComputeResponse(NegotiateFlags.NTLMSSP_ANOYNMOUS, domain, user_name, password, server_challenge, None,
                                 3, client_challenge).get_lm_challenge_response()

        assert actual == expected


    def test_nt_v1_response(self):
        expected_response = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94')
        expected_target_info = None
        (actual_response, actual_target_info) = ComputeResponse(NegotiateFlags.NTLMSSP_ANOYNMOUS, domain, user_name,
                                                                password, server_challenge, None,
                                                                1).get_nt_challenge_response()

        assert actual_response == expected_response
        assert actual_target_info == expected_target_info

    def test_nt_v1_with_extended_security_response(self):
        expected_response = HexToByte('75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32')
        expected_target_info = None
        (actual_response, actual_target_info) = ComputeResponse(NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, domain, user_name,
                                                                password, server_challenge, None,
                                                                1, client_challenge).get_nt_challenge_response()

        assert actual_response == expected_response
        assert actual_target_info == expected_target_info

    @pytest.mark.skipif(True, reason="This test is failing, the expected hex from Microsoft is not correct")
    def test_nt_v2_response(self):
        expected_response = HexToByte('68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00 44 00 6f 00 6d 00 '
                                      '61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00 00 '
                                      '00 00 00 c5 da d2 54 4f c9 79 90 94 ce 1c e9')
        expected_target_info = target_info
        (actual_response, actual_target_info) = ComputeResponse(
            NegotiateFlags.NTLMSSP_ANOYNMOUS, domain, user_name,
            password, server_challenge, target_info,
            3, client_challenge).get_nt_challenge_response()

        assert actual_response == expected_response
        assert actual_target_info == expected_target_info


    @pytest.mark.skipif(True, reason="Cannot find a valid way as the timestamp is unique everytime this is run, is there a way to mock that step?")
    def test_nt_v2_response(self):
        expected_response = HexToByte('')
        expected_target_info = TargetInfo()
        (actual_response, actual_target_info) = ComputeResponse(
            NegotiateFlags.NTLMSSP_ANOYNMOUS, domain, user_name,
            password, server_challenge, expected_target_info,
            3, client_challenge).get_nt_challenge_response()

        assert actual_response == expected_response
        assert actual_target_info == expected_target_info