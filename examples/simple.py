"""
Usage:  simple.py <password> <url>

This downloads an NTML-protected webpage to stdout.  The username is
constructed from the USERDOMAIN and USERNAME environment variables.
Note that the password is entered on the command line; this is almost
certainly a security risk but unfortunately I know of no foolproof
method in Python for prompting for a password from standard input.

This script only understands NTML authentication.
"""

import urllib2
import inspect, os, sys

try:
    from ntlm import HTTPNtlmAuthHandler
except ImportError:
    # assume ntlm is in the directory "next door"
    ntlm_folder = os.path.realpath(os.path.join(
        os.path.dirname(inspect.getfile(inspect.currentframe())),
        '..'))
    sys.path.insert(0, ntlm_folder)
    from ntlm import HTTPNtlmAuthHandler

def process(password, url):
    user = '%s\%s' % ( os.environ["USERDOMAIN"], os.environ["USERNAME"] )
    
    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, url, user, password)
    # create the NTLM authentication handler
    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
    
    # create and install the opener
    opener = urllib2.build_opener(auth_NTLM)
    urllib2.install_opener(opener)
    
    # retrieve the result
    response = urllib2.urlopen(url)
    print(response.read())

