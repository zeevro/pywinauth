from __future__ import print_function

import sys
import os
import binascii
import base64
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


def _normalize_name(name):
    return '_'.join(name.lower().split())


def _make_authenticator(secret, digits=6, digest='sha1', interval=30):
    return pyotp.TOTP(s=base64.b32encode(binascii.a2b_hex(secret)),
                      digits=int(digits),
                      digest=digest,
                      interval=int(interval))


def get_authenticators():
    xml_path = os.path.join(os.environ['APPDATA'], 'WinAuth', 'winauth.xml')
    with open(xml_path, 'rb') as f:
        xml_data = xmltodict.parse(f, force_list=['WinAuthAuthenticator'])
        authenticators = {_normalize_name(i['name']):
                          _make_authenticator(*i['authenticatordata']['secretdata'].split('\t'))
                          for i in xml_data['WinAuth']['WinAuthAuthenticator']
                          if i['@type'] == 'WinAuth.GoogleAuthenticator'}
    return authenticators


def main():
    try:
        authenticators = get_authenticators()
    except Exception as e:
        print('Could not load WinAuth configuration! {}'.format(e), file=sys.stderr)
        return 1

    if len(sys.argv) == 1:
        for name in sorted(authenticators):
            print(name)
        return

    if have_fuzzy:
        name, certainty, auth = process.extractOne(sys.argv[1], {v: k for k, v in authenticators.items()}, scorer=QRatio)
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

    code = auth.now()
    print(code)
    if have_pyperclip:
        pyperclip.copy(code)


if __name__ == "__main__":
    sys.exit(main())
