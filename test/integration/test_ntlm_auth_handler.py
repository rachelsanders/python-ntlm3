import unittest

from six.moves import urllib

from httpretty import HTTPretty, httprettified

from ntlm import HTTPNtlmAuthHandler

from ..fixtures import *  # noqa


class Test_NTLMAuthHandler(unittest.TestCase):
    def setUp(self):
        global counter
        counter = 0  # globals are gross, but they have their place


    @httprettified
    def test_normal_handshake(self):

        def request_callback(request, uri, headers):
            """
            The ntlm module makes three requests when
                1. The initial request, which should get a 401 and a www-authenticate: NTLM response
                2. The second request, which should contain our challenge response, and a Keep-Alive header
                3. The third request, where we pretend to have looked that shit up and give them what
                they wanted in the first place.
            """
            global counter

            counter += 1

            is_auth_request = request.headers.get('www-authenticate', None)
            is_auth_header_request = request.headers.get('authorization', None)

            # First response: initial challenge
            if not is_auth_request and counter == 1:
                headers.update(INITIAL_REJECTION_HEADERS)
                return (401, headers, INITIAL_REJECTION_BODY)

            # Second response: server challenge response
            if is_auth_header_request and counter == 2:
                # NTLM must authenticate the connection on the same socket

                assert request.headers.get('connection') == CONNECTION_KEEP_ALIVE

                headers.update(CHALLENGE_RESPONSE_HEADERS)
                return (401, headers, CHALLENGE_RESPONSE_BODY)

            # Third response: what they originally asked for
            if counter == 3:

                assert request.headers.get('connection') == CONNECTION_CLOSE

                headers.update(SUCCESSFUL_CONNECTION_HEADERS)
                return (200, headers, SUCCESSFUL_CONNECTION_BODY)

            for key in request.headers:
                print("{0}: {1}".format(key, request.headers[key]))

            raise AssertionError("The client sent something we didn't expect.")

        HTTPretty.register_uri(
            HTTPretty.GET, FAKE_URL,
            body=request_callback)

        passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, FAKE_URL, FAKE_USER, FAKE_PASSWORD)

        auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman, debuglevel=0)
        opener = urllib.request.build_opener(auth_NTLM)

        f = opener.open(FAKE_URL)
        assert f.read() == SUCCESSFUL_CONNECTION_BODY


    @httprettified
    def test_if_we_send_a_cookie_it_gets_sent_to_the_server(self):

        def request_callback(request, uri, headers):
            """
            The ntlm module makes three requests when
                1. The initial request, which should get a 401 and a www-authenticate: NTLM response
                2. The second request, which should contain our challenge response, and a Keep-Alive header
                3. The third request, where we pretend to have looked that shit up and give them what
                they wanted in the first place.
            """
            global counter

            counter += 1

            is_auth_request = request.headers.get('www-authenticate', None)
            is_auth_header_request = request.headers.get('authorization', None)

            # First response: initial challenge
            if not is_auth_request and counter == 1:
                headers.update(INITIAL_REJECTION_HEADERS)

                return (401, headers, INITIAL_REJECTION_BODY)

            # Second response: server challenge response
            if is_auth_header_request and counter == 2:
                headers.update(CHALLENGE_RESPONSE_HEADERS_WITH_COOKIE)
                return (401, headers, CHALLENGE_RESPONSE_BODY)

            # Third response: what they originally asked for
            if counter == 3:
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                # Make sure the cookie that the server "set" we pass back
                assert request.headers.get('cookie') == FAKE_COOKIE_VALUE
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                headers.update(SUCCESSFUL_CONNECTION_HEADERS)
                return (200, headers, SUCCESSFUL_CONNECTION_BODY)

            for key in request.headers:
                print("{0}: {1}".format(key, request.headers[key]))

            raise AssertionError("The client sent something we didn't expect.")

        HTTPretty.register_uri(
            HTTPretty.GET, FAKE_URL,
            body=request_callback)

        passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, FAKE_URL, FAKE_USER, FAKE_PASSWORD)

        auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman, debuglevel=0)
        opener = urllib.request.build_opener(auth_NTLM)

        f = opener.open(FAKE_URL)

        # The real tests is up in the callback function, this is just sanity testing
        assert f.read() == SUCCESSFUL_CONNECTION_BODY

