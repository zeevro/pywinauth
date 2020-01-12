from base64 import b32encode
from binascii import hexlify
from hashlib import sha1, sha256
from unittest import TestCase, main
from unittest.mock import patch, mock_open, Mock
from urllib.parse import urlparse, parse_qs
from uuid import uuid4

import winauth


SECRET_BYTES = b'abcde'
SECRET_HEX = hexlify(SECRET_BYTES).decode()
SECRET_ENCODED = b32encode(SECRET_BYTES).decode()

REGULAR_SECRET_DATA = (SECRET_HEX, 6, 'sha1', 30)
SPECIAL_SECRET_DATA = (SECRET_HEX, 8, 'sha1', 60)

def url2dict(url):
    parts = urlparse(url)
    d = {k: getattr(parts, k) for k in ('scheme', 'netloc', 'path')}
    d['query'] = parse_qs(parts.query)
    return d


class MyTOTP(TestCase):
    def test_regular(self):
        auth = winauth.MyTOTP('test', SECRET_HEX)

        self.assertEqual(auth.name, 'test')
        self.assertEqual(auth.byte_secret(), SECRET_BYTES)
        self.assertEqual(auth.digits, 6)
        self.assertEqual(auth.digest, sha1)
        self.assertEqual(auth.interval, 30)

    def test_args_order(self):
        auth = winauth.MyTOTP('test', SECRET_HEX, 14, 'sha256', 32)

        self.assertEqual(auth.name, 'test')
        self.assertEqual(auth.byte_secret(), SECRET_BYTES)
        self.assertEqual(auth.digits, 14)
        self.assertEqual(auth.digest, sha256)
        self.assertEqual(auth.interval, 32)

    def test_digits(self):
        auth = winauth.MyTOTP('test', SECRET_HEX, 8)
        self.assertEqual(auth.digits, 8)
        auth = winauth.MyTOTP('test', SECRET_HEX, '8')
        self.assertEqual(auth.digits, 8)
        with self.assertRaises(ValueError):
            winauth.MyTOTP('test', SECRET_HEX, 'x')

    def test_digest(self):
        auth = winauth.MyTOTP('test', SECRET_HEX, digest='sha256')
        self.assertEqual(auth.digest, sha256)

        digest = 'bad_digest_algo_asdf'
        with self.assertRaisesRegex(AttributeError, "module 'hashlib' has no attribute '{}'".format(digest)):
            winauth.MyTOTP('test', SECRET_HEX, digest=digest)

    def test_interval(self):
        auth = winauth.MyTOTP('test', SECRET_HEX, interval=60)
        self.assertEqual(auth.interval, 60)
        auth = winauth.MyTOTP('test', SECRET_HEX, interval='60')
        self.assertEqual(auth.interval, 60)
        with self.assertRaises(ValueError):
            winauth.MyTOTP('test', SECRET_HEX, interval='x')

    def test_url(self):
        self.assertDictEqual(url2dict(winauth.MyTOTP('test34', SECRET_HEX).url()),
                             url2dict('otpauth://totp/test34?secret={}'.format(SECRET_ENCODED)))

        self.assertDictEqual(url2dict(winauth.MyTOTP('test', SECRET_HEX, digits=8).url()),
                             url2dict('otpauth://totp/test?secret={}&digits=8'.format(SECRET_ENCODED)))

        self.assertDictEqual(url2dict(winauth.MyTOTP('test', SECRET_HEX, digest='sha256').url()),
                             url2dict('otpauth://totp/test?secret={}&algorithm=SHA256'.format(SECRET_ENCODED)))

        self.assertDictEqual(url2dict(winauth.MyTOTP('test', SECRET_HEX, interval=32).url()),
                             url2dict('otpauth://totp/test?secret={}&period=32'.format(SECRET_ENCODED)))

        self.assertDictEqual(url2dict(winauth.MyTOTP('test', SECRET_HEX, 14, 'sha256', 32).url()),
                             url2dict('otpauth://totp/test?secret={}&algorithm=SHA256&digits=14&period=32'.format(SECRET_ENCODED)))


# pylint: disable=protected-access
class NormalizeName(TestCase):
    def test_normal(self):
        self.assertEqual(winauth._normalize_name('asdf'), 'asdf')

    def test_whitespace(self):
        self.assertEqual(winauth._normalize_name('asdf qwer'), 'asdf_qwer')
        self.assertEqual(winauth._normalize_name('asdf  qwer'), 'asdf_qwer')
        self.assertEqual(winauth._normalize_name('asdf\tqwer'), 'asdf_qwer')

    def test_case(self):
        self.assertEqual(winauth._normalize_name('AsDf'), 'asdf')


XML_TEMPLATE = '''<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<WinAuth version="3.6">
  <alwaysontop>false</alwaysontop>
  <usetrayicon>true</usetrayicon>
  <notifyaction>Notification</notifyaction>
  <startwithwindows>true</startwithwindows>
  <autosize>true</autosize>
  <left>729</left>
  <top>216</top>
  <width>0</width>
  <height>0</height>{}
</WinAuth>'''

XML_AUTHENTICATOR_TEMPLATE = '''
  <WinAuthAuthenticator id="{id}" type="WinAuth.{type}">
    <name>{name}</name>
    <created>1534081256160</created>
    <autorefresh>false</autorefresh>
    <allowcopy>false</allowcopy>
    <copyoncode>true</copyoncode>
    <hideserial>false</hideserial>
    <skin>icon.png</skin>
    <authenticatordata>
      <servertimediff>-371</servertimediff>
      <lastservertime>637120459273709613</lastservertime>
      <secretdata>{secretdata}</secretdata>
    </authenticatordata>
  </WinAuthAuthenticator>'''


def make_xml(n_regular, n_special, n_invalid):
    auths = ({'id': uuid4(),
              'type': typ,
              'name': 'Auth {}'.format(i),
              'secretdata': '\t'.join(map(str, data))}
             for i, (typ, data) in enumerate(([('GoogleAuthenticator', REGULAR_SECRET_DATA)] * n_regular +
                                              [('GoogleAuthenticator', SPECIAL_SECRET_DATA)] * n_special +
                                              [('BAD', ())] * n_invalid),
                                             1))
    return XML_TEMPLATE.format(''.join(XML_AUTHENTICATOR_TEMPLATE.format(**auth) for auth in auths)).encode()


def urls_dict(auths):
    return {name: auth.url() for name, auth in auths.items()}


class GetAuthenticators(TestCase):
    @patch.dict('os.environ', {}, clear=True)
    def test_no_appdata_in_environ(self):
        with self.assertRaises(KeyError) as e:
            winauth.get_authenticators()
        self.assertEqual(e.exception.args[0], 'APPDATA')

    @patch.dict('os.environ', {'APPDATA': ''})
    @patch('winauth.open', Mock(side_effect=FileNotFoundError))
    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            winauth.get_authenticators()

    def test_custom_xml_path(self):
        test_path = 'This is a test path'
        mock = mock_open(read_data=make_xml(0, 0, 1))
        with patch('winauth.open', mock):
            winauth.get_authenticators(test_path)
        mock.assert_called_with(test_path, 'rb')

    @patch.dict('os.environ', {'APPDATA': ''})
    @patch('winauth.open', mock_open(read_data=make_xml(0, 0, 0)))
    def test_no_authenticators(self):
        self.assertEqual(winauth.get_authenticators(), {})

    @patch.dict('os.environ', {'APPDATA': ''})
    @patch('winauth.open', mock_open(read_data=make_xml(0, 0, 3)))
    def test_no_valid_authenticators(self):
        self.assertEqual(winauth.get_authenticators(), {})

    @patch.dict('os.environ', {'APPDATA': ''})
    @patch('winauth.open', mock_open(read_data=make_xml(1, 0, 3)))
    def test_one_valid_authenticator(self):
        self.assertDictEqual(urls_dict(winauth.get_authenticators()),
                             urls_dict({'auth_1': winauth.MyTOTP('Auth 1', *REGULAR_SECRET_DATA)}))

    @patch.dict('os.environ', {'APPDATA': ''})
    @patch('winauth.open', mock_open(read_data=make_xml(3, 0, 3)))
    def test_multiple_valid_authenticators(self):
        self.assertDictEqual(urls_dict(winauth.get_authenticators()),
                             urls_dict({'auth_1': winauth.MyTOTP('Auth 1', *REGULAR_SECRET_DATA),
                                        'auth_2': winauth.MyTOTP('Auth 2', *REGULAR_SECRET_DATA),
                                        'auth_3': winauth.MyTOTP('Auth 3', *REGULAR_SECRET_DATA)}))

    @patch.dict('os.environ', {'APPDATA': ''})
    @patch('winauth.open', mock_open(read_data=make_xml(0, 1, 0)))
    def test_special_authenticator(self):
        self.assertDictEqual(urls_dict(winauth.get_authenticators()),
                             urls_dict({'auth_1': winauth.MyTOTP('Auth 1', *SPECIAL_SECRET_DATA)}))


if __name__ == '__main__':
    main()
