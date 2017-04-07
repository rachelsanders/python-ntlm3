# Referenced from
# https://www.pythondiary.com/tutorials/django-ntlm-smtp-auth.html
# Downloaded from
# https://code.google.com/archive/p/python-ntlm/issues/14

# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

#from HTTPNtlmAuthHandler import asbase64
from .ntlm import create_NTLM_NEGOTIATE_MESSAGE, parse_NTLM_CHALLENGE_MESSAGE, create_NTLM_AUTHENTICATE_MESSAGE
from smtplib import SMTPException, SMTPAuthenticationError


def ntlm_authenticate(smtp, username, password):
#    """Example:
#    >>> import smtplib
#    >>> smtp = smtplib.SMTP("my.smtp.server")
#    >>> smtp.ehlo()
#    >>> ntlm_authenticate(smtp, r"DOMAIN\username", "password")
#    """
    args = "NTLM " + create_NTLM_NEGOTIATE_MESSAGE(username).decode("utf-8")

    code, response = smtp.docmd("AUTH", args)
    if code != 334:
        raise SMTPException("Server did not respond as expected to NTLM negotiate message")
    challenge, flags = parse_NTLM_CHALLENGE_MESSAGE(response)
    user_parts = username.split("\\", 1)
    args = create_NTLM_AUTHENTICATE_MESSAGE(challenge, user_parts[1], user_parts[0], password, flags)
    args = args.decode("utf-8")
    code, response = smtp.docmd("", args)
    if code != 235:
        raise SMTPAuthenticationError(code, response)
