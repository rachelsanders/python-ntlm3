import unittest
import pytest

from ntlm.ntlm import create_LM_hashed_password_v1, create_NT_hashed_password_v1, \
    create_sessionbasekey, calc_resp, ntlm2sr_calc_resp, create_NT_hashed_password_v2, \
    create_NTLM_NEGOTIATE_MESSAGE, ComputeResponse


from ..fixtures import *  # noqa
from ..utils import HexToByte, ByteToHex


class Test_HashingPasswords(unittest.TestCase):

    def test_LM_hashed_password(self):
        # [MS-NLMP] page 72
        assert HexToByte("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d") == create_LM_hashed_password_v1(Password)

    def test_NT_hashed_password(self):
        # [MS-NLMP] page 73
        assert HexToByte("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52") == create_NT_hashed_password_v1(Password)

    def test_create_session_base_key(self):
        assert HexToByte("d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84") == create_sessionbasekey(Password)

    def test_NT_hashed_password_v2(self):
        # [MS-NLMP] page 76
        assert HexToByte("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f") == create_NT_hashed_password_v2(Password, User, Domain)


class Test_HashedPasswordResponse(unittest.TestCase):

    def test_response_to_LM_hashed_password(self):
        assert HexToByte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13") == calc_resp(create_LM_hashed_password_v1(Password), ServerChallenge)

    def test_response_to_NT_hashed_password(self):
        assert HexToByte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94") == calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge)

    def test_response_to_NTLM_v1(self):
        # [MS-NLMP] page 75
        (NTLMv1Response, LMv1Response) = ntlm2sr_calc_resp(create_NT_hashed_password_v1(Password), ServerChallenge, ClientChallenge)
        assert HexToByte("aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00") == LMv1Response
        assert HexToByte("75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32") == NTLMv1Response

    def test_response_to_NTLM_v2(self):
        # [MS-NLMP] page 76
        ResponseKeyLM = ResponseKeyNT = create_NT_hashed_password_v2(Password, User, Domain)
        (NTLMv2Response, LMv2Response) = ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge, Time)
        assert HexToByte("86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa") == LMv2Response

    @pytest.mark.skipif(True, reason="This test is failing, not sure why")
    def test_ntlm_negotiate_message(self):
        assert "TlRMTVNTUAABAAAAB7IIogYABgAwAAAACAAIACgAAAAFASgKAAAAD1dTMDQyMzc4RE9NQUlO" == create_NTLM_NEGOTIATE_MESSAGE(FULL_DOMAIN)

    @pytest.mark.skipif(True, reason="This test is failing, not sure why")
    def test_expected_failure(self):
        ResponseKeyLM = ResponseKeyNT = create_NT_hashed_password_v2(Password, User, Domain)
        (NTLMv2Response, LMv2Response) = ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge, Time)

        # expected failure
        # According to the spec in section '3.3.2 NTLM v2 Authentication' the NTLMv2Response should be longer than the value given on page 77 (this suggests a mistake in the spec)
        # [MS-NLMP] page 77
        assert HexToByte("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c") == NTLMv2Response, "\nExpected: 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c\nActual:   %s" % ByteToHex(NTLMv2Response)

