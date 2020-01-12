from __future__ import print_function

import argparse
import sys
import warnings

from . import get_authenticators

try:
    import pyperclip
    have_pyperclip = True
except ImportError:
    have_pyperclip = False

try:
    warnings.filterwarnings('ignore', module='fuzzywuzzy')
    from fuzzywuzzy import process
    from fuzzywuzzy.fuzz import QRatio
    have_fuzzy = True
except ImportError:
    have_fuzzy = False

try:
    import qrcode
    have_qrcode = True
except ImportError:
    have_qrcode = False


def _output(s: str) -> None:
    if not s:
        return
    print(s)
    if have_pyperclip:
        try:
            pyperclip.copy(s)
        except Exception as e:
            print('Clipboard failed! {}'.format(e), file=sys.stderr)


def main() -> int:  # pylint: disable=inconsistent-return-statements
    p = argparse.ArgumentParser()
    p.add_argument('-x', '--xml-path')
    p.add_argument('--secret', dest='actions', action='append_const', const='secret')
    p.add_argument('--url', dest='actions', action='append_const', const='url')
    if have_qrcode:
        p.add_argument('--qr', dest='actions', action='append_const', const='qr')
    p.add_argument('name', nargs='?')
    args = p.parse_args()

    try:
        authenticators = get_authenticators(args.xml_path)
    except Exception as e:
        print('Could not load WinAuth configuration! {}'.format(e), file=sys.stderr)
        return 2

    if args.name is None:
        for name in sorted(authenticators):
            print(name)
        return 1

    if have_fuzzy:
        name, certainty, auth = process.extractOne(args.name, {v: k for k, v in authenticators.items()}, scorer=QRatio)
        if certainty < 15:
            print('Authenticator {} not found!'.format(sys.argv[1]), file=sys.stderr)
            return 1
        if certainty < 100:
            print('Guessed authenticator {}'.format(name), file=sys.stderr)
    else:
        try:
            auth = authenticators[args.name]
        except KeyError:
            print('Authenticator {} not found!'.format(sys.argv[1]), file=sys.stderr)
            return 1

    if not args.actions:
        _output(auth.now())
        return

    if 'secret' in args.actions:
        _output(auth.secret.decode())

    if 'url' in args.actions:
        _output(auth.url())

    if 'qr' in args.actions:
        qr = qrcode.QRCode()
        qr.add_data(auth.url())
        qr.print_ascii(invert=True)


if __name__ == '__main__':
    sys.exit(main())
