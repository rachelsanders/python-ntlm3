"""
Usage:  extended.py <password> <url>

This downloads an NTML-protected webpage to stdout.  The username is
constructed from the USERDOMAIN and USERNAME environment variables.
Note that the password is entered on the command line; this is almost
certainly a security risk but unfortunately I know of no foolproof
method in Python for prompting for a password from standard input.

This script associates the password with all URLs using the same base
URI.  Although we only connect to a single URL, this would allow
access to all resources within a single domain.  This script also
allows the use of basic and digest authentication as well as NTML.
Finally, it disables the use of proxies, which would prevent it from
leaving most corporate domains (which typically route external
requests through a proxy server).
"""

import urllib2
from urlparse import urlparse, urlunparse
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

    # determine a base_uri for which the username and password can be used
    parsed_url = urlparse(url)
    base_uri = urlunparse((parsed_url[0],parsed_url[1],"","","",""))
    
    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, base_uri, user, password)
    # create the NTLM authentication handler
    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
    
    # other authentication handlers
    auth_basic = urllib2.HTTPBasicAuthHandler(passman)
    auth_digest = urllib2.HTTPDigestAuthHandler(passman)
    
    # disable proxies (if you want to stay within the corporate network)
    proxy_handler = urllib2.ProxyHandler({})
    
    # create and install the opener
    opener = urllib2.build_opener(proxy_handler, auth_NTLM, auth_digest, auth_basic)
    urllib2.install_opener(opener)
    
    # retrieve the result    
    response = urllib2.urlopen(url)
    print(response.read())
