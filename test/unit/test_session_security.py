import unittest2 as unittest # for compatiblity with older version of python

from ntlm3.constants import NegotiateFlags
from ntlm3.session_security import SessionSecurity
from ..expected_values import *

default_negotiate_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL

class Test_SessionSecurity(unittest.TestCase):
    def test_invalid_source_param(self):
        test_flags = ntlmv1_negotiate_flags
        with self.assertRaises(Exception) as context:
            SessionSecurity(test_flags, session_base_key, source="unknown")

        self.assertTrue('Invalid source parameter unknown, must be client or server' in context.exception.args)

    def test_sign_and_seal_message_ntlm1(self):
        test_flags = ntlmv1_negotiate_flags
        test_session_security = SessionSecurity(test_flags, session_base_key)

        expected_seal = ntlmv1_output_message
        expected_sign = ntlmv1_signature

        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)

        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_sign_and_seal_message_ntlm2_no_key_exchange(self):
        test_flags = ntlmv1_with_ess_negotiate_flags
        test_session_security = SessionSecurity(test_flags, ntlmv1_with_ess_key_exchange_key)

        expected_seal = ntlmv1_with_ess_output_message
        expected_sign = ntlmv1_with_ess_signature

        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)

        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_sign_and_seal_message_ntlm2_key_exchange(self):
        test_flags = ntlmv2_negotiate_flags
        test_session_security = SessionSecurity(test_flags, session_base_key)

        expected_seal = ntlmv2_output_message
        expected_sign = ntlmv2_signature

        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)

        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_unseal_message_ntlm1(self):
        test_flags = ntlmv1_negotiate_flags
        test_session_security = SessionSecurity(test_flags, ntlmv1_key_exchange_key)
        test_server_session_security = SessionSecurity(test_flags, ntlmv1_key_exchange_key, source="server")
        test_message, test_signature = test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data

        actual_data = test_session_security.unwrap(test_message, test_signature)

        assert actual_data == expected_data

    def test_unseal_message_ntlm2_no_key_exchange(self):
        test_flags = ntlmv1_with_ess_negotiate_flags
        test_session_security = SessionSecurity(test_flags, ntlmv1_with_ess_key_exchange_key)
        test_server_session_security = SessionSecurity(test_flags, ntlmv1_with_ess_key_exchange_key, source="server")
        test_message, test_signature = test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data

        actual_data = test_session_security.unwrap(test_message, test_signature)

        assert actual_data == expected_data

    def test_unseal_message_ntlm2_key_exchange(self):
        test_flags = ntlmv2_negotiate_flags
        test_session_security = SessionSecurity(test_flags, session_base_key)
        test_server_session_security = SessionSecurity(test_flags, session_base_key, source="server")
        test_message, test_signature = test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data

        actual_data = test_session_security.unwrap(test_message, test_signature)

        assert actual_data == expected_data

    def test_unseal_message_incorrect_checksum(self):
        test_flags = ntlmv2_negotiate_flags
        test_session_security = SessionSecurity(test_flags, session_base_key)
        test_server_session_security = SessionSecurity(test_flags, session_base_key, source="server")
        test_message, test_signature = test_server_session_security.wrap(plaintext_data)
        # Overwrite signature to produce a bad checksum
        test_signature = HexToByte('01 00 00 00 b1 98 b8 47 ce 7c 58 07 00 00 00 00')

        with self.assertRaises(Exception) as context:
            test_session_security.unwrap(test_message, test_signature)

        self.assertTrue('The signature checksum does not match, message has been altered' in context.exception.args)

    def test_unseal_message_incorrect_seq_num(self):
        test_flags = ntlmv2_negotiate_flags
        test_session_security = SessionSecurity(test_flags, session_base_key)
        test_server_session_security = SessionSecurity(test_flags, session_base_key, source="server")
        test_message, test_signature = test_server_session_security.wrap(plaintext_data)
        # Overwrite signature to produce a bad checksum
        test_signature = HexToByte('01 00 00 00 b2 98 b8 47 ce 7c 58 07 00 00 00 01')

        with self.assertRaises(Exception) as context:
            test_session_security.unwrap(test_message, test_signature)

        self.assertTrue('The signature sequence number does not mathc up, message not received in the correct sequence' in context.exception.args)
