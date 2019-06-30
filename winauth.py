from __future__ import print_function

import sys
import os
import binascii
import base64
import hashlib
import xmltodict
import pyotp

try:
    import pyperclip
    have_pyperclip = True
except:
    have_pyperclip = False

try:
    import warnings
    warnings.filterwarnings('ignore', module='fuzzywuzzy')
    from fuzzywuzzy import process
    from fuzzywuzzy.fuzz import QRatio
    have_fuzzy = True
except:
    have_fuzzy = False

try:
    import qrcode
    have_qrcode = True
except:
    have_qrcode = False


class MyTOTP(pyotp.TOTP):
    def __init__(self, name, secret, digits=6, digest='sha1', interval=30):
        self.name = name
        super().__init__(s=base64.b32encode(binascii.a2b_hex(secret)),
                         digits=int(digits),
                         digest=getattr(hashlib, digest.lower()),
                         interval=int(interval))

    def url(self):
        return self.provisioning_uri(self.name)


def _normalize_name(name):
    return '_'.join(name.lower().split())


def get_authenticators():
    xml_path = os.path.join(os.environ['APPDATA'], 'WinAuth', 'winauth.xml')
    with open(xml_path, 'rb') as f:
        xml_data = xmltodict.parse(f, force_list=['WinAuthAuthenticator'])
        authenticators = {_normalize_name(i['name']):
                          MyTOTP(i['name'], *i['authenticatordata']['secretdata'].split('\t'))
                          for i in xml_data['WinAuth']['WinAuthAuthenticator']
                          if i['@type'] == 'WinAuth.GoogleAuthenticator'}
    return authenticators


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--secret', action='store_true')
    p.add_argument('--url', action='store_true')
    if have_qrcode:
        p.add_argument('--qr', action='store_true')
    p.add_argument('name', nargs='?')
    args = p.parse_args()

    try:
        authenticators = get_authenticators()
    except Exception as e:
        print('Could not load WinAuth configuration! {}'.format(e), file=sys.stderr)
        return 1

    if args.name is None:
        for name in sorted(authenticators):
            print(name)
        return

    if have_fuzzy:
        name, certainty, auth = process.extractOne(args.name, {v: k for k, v in authenticators.items()}, scorer=QRatio)
        if certainty < 15:
            print('Authenticator {} not found!'.format(sys.argv[1]), file=sys.stderr)
            return 1
        elif certainty < 100:
            print('Guessed authenticator {}'.format(name), file=sys.stderr)
    else:
        try:
            auth = authenticators[name]
        except KeyError:
            print('Authenticator {} not found!'.format(sys.argv[1]), file=sys.stderr)
            return 1

    output = None
    if args.secret:
        output = auth.secret.decode()
    elif args.url:
        output = auth.url()
    elif args.qr:
        qr = qrcode.QRCode()
        qr.add_data(auth.url())
        qr.print_ascii(invert=True)
    else:
        output = auth.now()

    if output is not None:
        print(output)
        if have_pyperclip:
            pyperclip.copy(output)


if __name__ == '__main__':
    sys.exit(main())
