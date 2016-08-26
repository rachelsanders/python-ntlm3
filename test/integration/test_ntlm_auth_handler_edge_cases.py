import unittest2 as unittest
import pytest
from httpretty import HTTPretty, httprettified, Response

from ntlm3 import HTTPNtlmAuthHandler

from ..fixtures import *  # noqa
from ..utils import MockRawServerResponse

from six.moves import urllib


class Test_NTLMAuthHandler_Issues(unittest.TestCase):

    @httprettified
    def test_duplicate_authenticate_headers(self):
        """
        Handle HTTP responses with more than one WWW-Authenticate header.

        Some servers send two WWW-Authenticate headers: one with the NTLM
        challenge and another with the 'Negotiate' phrase. Make sure we
        operate on the right header.

        Originally this issue: https://code.google.com/p/python-ntlm/issues/detail?id=27

        """

        HTTPretty.register_uri(
            HTTPretty.GET, FAKE_URL,
            responses=[
                Response(status=401, body="", forcing_headers=INITIAL_REJECTION_HEADERS),
                MockRawServerResponse(
                    status="401",
                    raw_response=DUPLICATE_HEADERS),
                Response(status=200, body=SUCCESSFUL_CONNECTION_BODY, forcing_headers=SUCCESSFUL_CONNECTION_HEADERS),
            ]
        )

        passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, FAKE_URL, FAKE_USER, FAKE_PASSWORD)

        auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman, debuglevel=0)
        opener = urllib.request.build_opener(auth_NTLM)

        f = opener.open(FAKE_URL)

        response = f.read()

        assert response == SUCCESSFUL_CONNECTION_BODY

    @httprettified
    def test_structure_presence_flag_is_checked(self):
        """
        Before attempting to unpack TargetInfo structure presence flag must be checked.

        Originally this issue: https://code.google.com/p/python-ntlm/issues/detail?id=28
        """
        HTTPretty.register_uri(
            HTTPretty.GET, FAKE_URL,
            responses=[
                Response(status=401, body="", forcing_headers=INITIAL_REJECTION_HEADERS),
                MockRawServerResponse(
                    status="401",
                    raw_response=AUTH_TOO_SHORT_RESPONSE),
                Response(status=200, body=SUCCESSFUL_CONNECTION_BODY, forcing_headers=SUCCESSFUL_CONNECTION_HEADERS),
                ]
        )

        passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, FAKE_URL, FAKE_USER, FAKE_PASSWORD)

        auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman, debuglevel=0)
        opener = urllib.request.build_opener(auth_NTLM)

        f = opener.open(FAKE_URL)

        response = f.read()

        assert response == SUCCESSFUL_CONNECTION_BODY

    @httprettified
    def test_that_if_ntlm_is_not_in_the_header_we_do_shitty_behavior(self):
        """ This test is here to remind me ff NTLM isn't in the header
        we basically hang forever :/ """
        HTTPretty.register_uri(
            HTTPretty.GET, FAKE_URL,
            responses=[
                Response(status=401, body="", forcing_headers=BASIC_AUTH_HEADERS),
                ]
        )

    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, FAKE_URL, FAKE_USER, FAKE_PASSWORD)

    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman, debuglevel=0)
    opener = urllib.request.build_opener(auth_NTLM)

    with pytest.raises(urllib.error.URLError):
        f = opener.open(FAKE_URL, timeout=0)
