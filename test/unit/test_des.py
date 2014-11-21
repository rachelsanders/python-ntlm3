import unittest

from ntlm.des import DES


class Test_Encryption(unittest.TestCase):

    def test_decryption_is_the_opposite_of_encryption(self):
        des_obj = DES("rando_key_str")
        SAMPLE_TEXT = "abcdefgh"

        assert des_obj.decrypt(des_obj.encrypt(SAMPLE_TEXT)) == SAMPLE_TEXT

    def test_long_strings_are_truncated_to_eight_characters(self):
        """ I'm not entirely sure this is *wanted* behavior, but it is *current* behavior* """
        des_obj = DES("rando_key_str")
        SAMPLE_TEXT = "abcdefghijklmnopqrstuvwxyz"

        assert des_obj.decrypt(des_obj.encrypt(SAMPLE_TEXT)) == SAMPLE_TEXT[0:8]
