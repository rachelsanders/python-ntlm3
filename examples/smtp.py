#! /usr/bin/env python

"""
A simple script to demonstrate how this package works with an SMTP server.

Run with:

    python simple.py --username "DOMAIN\\username" --host "some.smtp.server" --port 25 --fromE "my@email.com" --subject "some subject" --body "some body"

The script will prompt you for a password, or you can specify one with --password <password> if you prefer.

Inspired from
https://docs.python.org/2/library/smtplib.html#smtp-example
and
https://docs.python.org/2/library/email-examples.html#email-examples

"""
import getpass

try:
    import argparse
except ImportError:
    raise SystemExit("Hi, I see you're on Python 2.6. Please run 'pip install argparse' and try again.")

import ntlm3 as ntlm
import smtplib
from email.mime.text import MIMEText

def process(user, password, host, port, fromE, to, subject, body):
    smtp = smtplib.SMTP(host, port)
    smtp.set_debuglevel(True)
    smtp.ehlo()
    ntlm.smtp.ntlm_authenticate(smtp, user, password)
    msg = MIMEText(body)
    msg['Subject']=subject
    msg['From']=fromE
    msg['To']=to
    smtp.sendmail(fromE, [to], msg.as_string())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--host', help='A SMTP server with NTLM auth', required=True)
    parser.add_argument('-u', '--username', help='Your username, in the form "DOMAIN\\username"', required=True)
    parser.add_argument('-p', '--password', help='Your password. Optional, the script will prompt for it.')
    parser.add_argument('-l', '--port', help='server port number')
    parser.add_argument('-f', '--fromE', help='from email to use')
    parser.add_argument('-t', '--to', help='to email')
    parser.add_argument('-s', '--subject', help='email subject')
    parser.add_argument('-b', '--body', help='email body')

    args = parser.parse_args()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass()

    process(user=args.username, password=password, host=args.host, port=args.port, to=args.to, fromE=args.fromE, subject=args.subject, body=args.body)
