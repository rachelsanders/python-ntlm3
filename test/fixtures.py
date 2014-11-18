from .utils import HexToByte

ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
ClientChallenge = b'\xaa'*8
Time = b'\x00'*8
Workstation = "COMPUTER".encode('utf-16-le')
ServerName = "Server".encode('utf-16-le')
User = "User"
Domain = "Domain"
Password = "Password"
RandomSessionKey = '\55'*16

FULL_DOMAIN = '%s\\%s' % (Domain, User)