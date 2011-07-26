"""
Test suite for hkp Python module.
"""

import datetime
import time
import os
import unittest
from random import choice
from hkp import KeyServer, Identity, Key
from hkp.client import ALGORITHMS
from dingus import patch, Dingus
from urllib import urlencode


__all__ = ['TestKeyServer', 'TestIdentity', 'TestKey']

#Tests are isolated from network, so keyserver is not really hit.
KEY_SERVER = 'http://pool.sks-keyservers.net'

PORT = 11371

# Ubuntu key data
FINGERPRINT = '0x46181433FBB75451'
KEYID = '0x%s' % FINGERPRINT[-8:]
UID = 'Ubuntu CD Image Automatic Signing Key'
DINGUS = Dingus()


def load_fixture(name):
    """
    Return a file-like fixture, just like urlopen would.
    """
    return open(os.path.join(
            os.path.abspath(os.path.dirname(__file__)),
            name,
            ),
        'r'
        )


class TestKeyServer(unittest.TestCase):
    """
    Unit test for KeyServer class.
    """

    def setUp(self):
        """
        Set up random KeyServer.
        """
        self.server_host = KEY_SERVER
        self.serv = KeyServer(self.server_host)
        self.begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        self.end_header = '-----END PGP PUBLIC KEY BLOCK-----'
        DINGUS.reset()
        DINGUS.return_value = load_fixture('search_answer')

    def test_init(self):
        """
        Test KeyServer constructor.
        """
        self.assertEqual(self.serv.host, self.server_host)
        self.assertEqual(self.serv.port, PORT)

    @patch('urllib2.urlopen', DINGUS)
    def test_search_by_id(self):
        """
        Test search with keyid.
        """
        result = self.serv.search(KEYID)
        search_url = (self.server_host + ':11371/pks/lookup'
                '?search=0xFBB75451&exact=off&options=mr&op=index')
        self.assertTrue(DINGUS.calls('()', search_url).once())
        self.assertEqual(len(result), 1)
        result[0].keyid = KEYID
        result[0].identities[0].uid = UID

    @patch('urllib2.urlopen', DINGUS)
    def test_search_by_fingerprint(self):
        """
        Test search with fingerprint.
        """
        result = self.serv.search(FINGERPRINT)
        search_url = (self.server_host + ':11371/pks/lookup'
                '?search=0x46181433FBB75451&exact=off&options=mr&op=index')
        self.assertTrue(DINGUS.calls('()', search_url).once())
        self.assertEqual(len(result), 1)
        result[0].keyid = KEYID
        result[0].identities[0].uid = UID

    @patch('urllib2.urlopen', DINGUS)
    def test_search_by_uid(self):
        """
        Test search with uid.
        """
        result = self.serv.search(UID)
        search_url = (self.server_host + ':11371/pks/lookup'
                '?search=Ubuntu+CD+Image+Automatic+Signing+Key'
                '&exact=off&options=mr&op=index')
        self.assertTrue(DINGUS.calls('()', search_url).once())
        self.assertEqual(len(result), 1)
        result[0].keyid = KEYID
        result[0].identities[0].uid = UID

    @patch('urllib2.urlopen', DINGUS)
    def test_add(self):
        """
        Test ASCII armored key upload
        """
        stored_key = 'ubuntu.key'
        key = load_fixture(stored_key).read()
        keytext = '%s\n\n%s\n%s' % (
            self.begin_header,
            key,
            self.end_header,
        )

        self.serv.add(keytext)

        add_url = self.server_host + ':11371/pks/add'
        self.assertTrue(DINGUS.calls('()', add_url,
            urlencode({'keytext': keytext})
            ).once())


class TestIdentity(unittest.TestCase):
    """
    Unit test for Identity class.
    """

    def setUp(self):
        """
        Set up Identity data.
        """
        self.uid = 'Test identity~'
        self.uid_q = 'Test identity%7E'
        self.creation_date = time.time()
        self.expiration_date = time.time()
        self.flags = 're'

    def test_init(self):
        """
        Test Identity constructor.
        """
        identity = Identity(
            self.uid_q,
            self.creation_date,
            self.expiration_date,
            self.flags,
        )
        self.assertTrue(identity.revoked)
        self.assertTrue(identity.expired)
        self.assertFalse(identity.disabled)
        self.assertEqual(self.uid, identity.uid)
        creation_date = datetime.datetime.fromtimestamp(self.creation_date)
        self.assertEqual(
            identity.creation_date,
            creation_date.replace(microsecond=0),
        )
        expiration_date = datetime.datetime.fromtimestamp(self.expiration_date)
        self.assertEqual(
            identity.expiration_date,
            expiration_date.replace(microsecond=0),
        )


class TestKey(unittest.TestCase):
    """
    Unit test for Key class.
    """

    def setUp(self):
        """
        Set up Key data.
        """
        self.server_host = KEY_SERVER
        self.algo = str(choice(ALGORITHMS.keys()))
        self.key_length = '2048'
        self.creation_date = time.time()
        self.expiration_date = time.time()
        self.flags = 'dr'
        self.stored_key = 'ubuntu.key'
        self.begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        self.end_header = '-----END PGP PUBLIC KEY BLOCK-----'
        self.key_answer = load_fixture('ubuntu.html')
        DINGUS.reset()

    def test_init(self):
        """
        Test Key constructor.
        """
        key = Key(
            self.server_host,
            PORT,
            KEYID,
            self.algo,
            self.key_length,
            self.creation_date,
            self.expiration_date,
            self.flags,
        )

        self.assertEqual(key.host, self.server_host)
        self.assertEqual(key.port, PORT)
        self.assertEqual(key.keyid, KEYID)

        self.assertEqual(key.algo, ALGORITHMS[int(self.algo)])
        self.assertEqual(key.key_length, int(self.key_length))

        self.assertTrue(key.revoked)
        self.assertTrue(key.disabled)
        self.assertFalse(key.expired)

        creation_date = datetime.datetime.fromtimestamp(self.creation_date)
        self.assertEqual(
            key.creation_date,
            creation_date.replace(microsecond=0),
        )
        expiration_date = datetime.datetime.fromtimestamp(self.expiration_date)
        self.assertEqual(
            key.expiration_date,
            expiration_date.replace(microsecond=0),
        )

    @patch('urllib2.urlopen', DINGUS)
    def test_key(self):
        """
        Retrieve Ubuntu ASCII armored public key and check it.
        """
        key = Key(
            self.server_host,
            PORT,
            KEYID,
            self.algo,
            self.key_length,
            self.creation_date,
            self.expiration_date,
            self.flags,
        )
        DINGUS.return_value = self.key_answer
        stored_key = load_fixture(self.stored_key).read()

        # key property is absent before first call
        self.assertFalse('key' in key.__dict__)

        # we can't just check equality as Version may vary
        self.assertTrue(stored_key in key.key)
        self.assertTrue(key.key.startswith(self.begin_header))
        self.assertTrue(key.key.endswith(self.end_header))

        # key property is there, lazy property works!
        self.assertTrue('key' in key.__dict__)


if __name__ == '__main__':
    unittest.main()
