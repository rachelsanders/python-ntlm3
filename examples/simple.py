#! /usr/bin/env python

"""
A simple script to demonstrate how this package works.

Run with:

    python simple.py --username "DOMAIN\\username" --url "http://some.protected/url"

The script will prompt you for a password, or you can specify one with --password <password> if you prefer.

"""
import sys
from six.moves import urllib
import getpass

try:
    import argparse
except ImportError:
    raise SystemExit("Hi, I see you're on Python 2.6. Please run 'pip install argparse' and try again.")

import ntlm

def process(user, password, url):

    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None,  url, user, password)

    # create the NTLM authentication handler
    auth_NTLM = ntlm.HTTPNtlmAuthHandler(passman)

    opener = urllib.request.build_opener(auth_NTLM)

    response = opener.open(url)

    print(response.read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', help='A url protected behind NTLM auth', required=True)
    parser.add_argument('-u', '--username', help='Your username, in the form "DOMAIN\\username"', required=True)
    parser.add_argument('-p', '--password', help='Your password. Optional, the script will prompt for it.')

    args = parser.parse_args()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass()

    process(user=args.username, password=password, url=args.url)
