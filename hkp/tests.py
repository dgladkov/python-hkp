import datetime
import time
import os
import unittest
from random import choice
from hkp import KeyServer, Identity, Key
from hkp.client import ALGORITHMS


__all__ = ['TestKeyServer', 'TestIdentity', 'TestKey']

KEY_SERVERS = (
    'http://pool.sks-keyservers.net',
    'http://pgp.mit.edu',
)

PORT = 11371

# Ubuntu key data
FINGERPRINT = '0x46181433FBB75451'
KEYID = '0x%s' % FINGERPRINT[-8:]
UID = 'Ubuntu CD Image Automatic Signing Key'


class TestKeyServer(unittest.TestCase):
    """
    Unit test for KeyServer class.
    """

    def setUp(self):
        """
        Set up random KeyServer.
        """
        self.server_host = choice(KEY_SERVERS)
        self.serv = KeyServer(self.server_host)

    def test_init(self):
        """
        Test KeyServer constructor.
        """
        self.assertEqual(self.serv.host, self.server_host)
        self.assertEqual(self.serv.port, PORT)

    def test_search(self):
        """
        Test search with keyid, fingerprint and uid.
        """
        result = self.serv.search(KEYID)
        self.assertEqual(len(result), 1)
        result[0].keyid = KEYID
        result[0].identities[0].uid = UID

        result = self.serv.search(FINGERPRINT)
        self.assertEqual(len(result), 1)
        result[0].keyid = KEYID
        result[0].identities[0].uid = UID

        result = self.serv.search(UID)
        self.assertEqual(len(result), 1)
        result[0].keyid = KEYID
        result[0].identities[0].uid = UID


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
        self.server_host = choice(KEY_SERVERS)
        self.algo = str(choice(ALGORITHMS.keys()))
        self.key_length = '2048'
        self.creation_date = time.time()
        self.expiration_date = time.time()
        self.flags = 'dr'
        self.stored_key = os.path.join(
            os.path.abspath(os.path.dirname(__file__)),
            'ubuntu.key',
        )

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

        stored_key = open(self.stored_key, 'r').read()

        # key property is absent before first call
        self.assertFalse('key' in key.__dict__)

        # we can't just check equity as Version may vary
        self.assertIn(stored_key, key.key)
        self.assertTrue(key.key.startswith(key._begin_header))
        self.assertTrue(key.key.endswith(key._end_header))

        # key property is there, lazy property works!
        self.assertTrue('key' in key.__dict__)


if __name__ == '__main__':
    unittest.main()
