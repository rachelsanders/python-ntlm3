from binascii import unhexlify

from httpretty.core import text_type, utf8

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    return ' '.join( [ "%02X" % x for x in byteStr ] )


def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    hexStr = ''.join( hexStr.split(" ") )

    return unhexlify(hexStr)


class MockRawServerResponse(object):

    def __init__(self, method=None, status=200, uri=None, raw_response=None):

        self.method = method
        self.uri = uri
        self.info = None
        self.request = None

        self.status = int(status)

        if isinstance(raw_response, text_type):
            self.raw_response = utf8(raw_response)
        else:
            self.raw_response = raw_response

    def fill_filekind(self, fk):

        fk.write(utf8(self.raw_response))
        fk.seek(0)
