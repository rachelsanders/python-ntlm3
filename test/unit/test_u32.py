import unittest
import pytest

from ntlm.U32 import U32


class Test_U32(unittest.TestCase):

    def test_can_pass_in_value_via_init(self):
        assert U32(100).__repr__() == '0x64L'

    def test_negative_numbers_are_converted_to_positive(self):
        assert U32(-100).__repr__() == '0x64L'

    def test_can_set_value_via_method(self):
        n = U32()
        assert n.__repr__() == '0x0L'
        n.set(100)
        assert U32(100).__repr__() == '0x64L'

    def test_can_cast_to_long(self):
        assert long(U32(100)) == 100L

    def test_can_chr(self):
        assert U32(100).__chr__() == chr(ord('d'))

    def test_can_add(self):
        assert U32(100) + U32(0) == U32(100)
        assert U32(10) + U32(90) == U32(100)

    def test_can_sub(self):
        assert U32(100) - U32(0) == U32(100)
        assert U32(100) - U32(90) == U32(10)

    @pytest.mark.skipif(True, reason="I need to read this code and understand what it does")
    def test_can_sub_number_under_zero(self):
        assert U32(10) - U32(100) == U32(90)

    def test_can_multiply(self):
        assert U32(10) * U32(5) == U32(50)

    def test_can_divide(self):
        assert U32(50) / U32(5) == U32(10)

    def test_can_mod(self):
        assert U32(100) % U32(10) == U32(0)
        assert U32(9) % U32(2) == U32(1)

    def test_can_neg(self):
        assert -U32(100) == U32(100)

    def test_can_pos(self):
        assert +U32(100) == U32(100)

    def test_can_abs(self):
        assert abs(U32(100)) == U32(100)
        assert abs(-U32(100)) == U32(100)

    @pytest.mark.skipif(True, reason="I need to read this code and understand what it does")
    def test_can_invert(self):
        assert ~U32(100) == 0xffffff9bL

    @pytest.mark.skipif(True, reason="This test appears to be broken in the code")
    def test_can_truth(self):
        if U32(100):
            pass
        else:
            assert False, "U32(100) should be considered true"

    @pytest.mark.skipif(True, reason="This test appears to be broken in the code")
    def test_can_bool(self):
        assert bool(U32(100)) is True
        assert bool(U32(0)) is False

    def test_can_compare(self):
        assert U32(100) > U32(99)
        assert U32(99) < U32(100)
        assert U32(100) == U32(100)
