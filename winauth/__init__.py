from __future__ import print_function

from base64 import b32encode
from binascii import unhexlify
import hashlib
import os
from typing import Union, Dict, AnyStr

import pyotp
import xmltodict


__all__ = ['get_authenticators']


class MyTOTP(pyotp.TOTP):
    def __init__(self,
                 name: str,
                 secret: AnyStr,
                 digits: Union[str, int] = 6,
                 digest: str = 'sha1',
                 interval: Union[str, int] = 30):
        self.name = name
        super().__init__(s=b32encode(unhexlify(secret)),
                         digits=int(digits),
                         digest=getattr(hashlib, digest.lower()),
                         interval=int(interval))

    def url(self) -> str:
        return self.provisioning_uri(self.name)


def _normalize_name(name: str) -> str:
    return '_'.join(name.lower().split())


def get_authenticators(xml_path: Union[str, None] = None) -> Dict[str, MyTOTP]:
    if not xml_path:
        xml_path = os.path.join(os.environ['APPDATA'], 'WinAuth', 'winauth.xml')
    with open(xml_path, 'rb') as f:
        xml_data = xmltodict.parse(f, force_list=['WinAuthAuthenticator'])
        if 'WinAuthAuthenticator' not in xml_data['WinAuth']:
            return {}
        authenticators = {_normalize_name(i['name']):
                          MyTOTP(i['name'], *i['authenticatordata']['secretdata'].split('\t'))
                          for i in xml_data['WinAuth']['WinAuthAuthenticator']
                          if i['@type'] == 'WinAuth.GoogleAuthenticator'}
    return authenticators
