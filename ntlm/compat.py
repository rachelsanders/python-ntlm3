import six

def _long(value):
    try:
        return long(value)
    except NameError:  # we're Python 3, we don't have longs
        return int(value)


def cast_to_bytestring(value):
    if not isinstance(value, six.binary_type):
        if six.PY2:
            value = str(value)
        else:
            value = bytes(value)

    return value