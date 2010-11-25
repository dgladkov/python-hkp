"""
Python HKP procol client implementation based on current draft spec
http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
"""

from datetime import datetime
import urllib
import urllib2
from hkp.utils import cached_property


__all__ = ['Key', 'Identity', 'KeyServer']

# Loosely taken from RFC2440 (http://tools.ietf.org/html/rfc2440#section-9.1)
ALGORITHMS = {
    1: 'RSA (Encrypt or Sign)',
    2: 'RSA Encrypt-Only',
    3: 'RSA Sign-Only',
    16: 'Elgamal (Encrypt-Only)',
    17: 'DSA (Digital Signature Standard)',
    18: 'Elliptic Curve',
    19: 'ECDSA',
    20: 'Elgamal (Encrypt or Sign)',
}


class Key(object):
    """
    Public key object.
    """

    _begin_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    _end_header = '-----END PGP PUBLIC KEY BLOCK-----'

    def __init__(self, host, port, keyid, algo, keylen,
                 creation_date, expiration_date, flags):
        """
        Takes keyserver host and port used to look up ASCII armored key, and
        data as it is present in search query result.
        """
        self.host = host
        self.port = port
        self.keyid = keyid
        algo = int(algo)
        self.algo = ALGORITHMS.get(algo, algo)
        self.key_length = int(keylen)
        self.creation_date = datetime.fromtimestamp(int(creation_date))

        if expiration_date:
            self.expiration_date = datetime.fromtimestamp(int(expiration_date))
        else:
            self.expiration_date = None

        self.revoked, self.disabled, self.expired = [False] * 3

        if 'r' in flags:
            self.revoked = True
        if 'd' in flags:
            self.disabled = True
        if 'e' in flags:
            self.expired = True

        self.identities = []

    def __repr__(self):
        return 'Key %s %s' % (self.keyid, self.algo)

    def __str__(self):
        return repr(self)

    @cached_property
    def key(self, nm=False):
        """
        Retrieve public key from keyserver and strip off any enclosing HTML.
        """
        opts = (
            ('mr', True), ('nm', nm),
        )

        keyid = self.keyid
        params = urllib.urlencode({
            'search': keyid.startswith('0x') and keyid or '0x%s' % keyid,
            'op': 'get',
            'options': ','.join(name for name, val in opts if val),
        })

        request_url = '%s:%d/pks/lookup?%s' % (self.host, self.port, params)
        response = urllib2.urlopen(request_url).read()
        # strip off encosing text or HTML. According to RFC headers MUST be
        # always preverved, so we rely on them
        key = response.split(self._begin_header)[1].split(self._end_header)[0]
        return '%s%s%s' % (self._begin_header, key, self._end_header)


class Identity(object):
    """
    Key owner's identity. Constructor takes data as it is present in search
    query result.
    """

    def __init__(self, uid, creation_date, expiration_date, flags):
        self.uid = urllib2.unquote(uid)

        if creation_date:
            self.creation_date = datetime.fromtimestamp(int(creation_date))
        else:
            self.creation_date = None

        if expiration_date:
            self.expiration_date = datetime.fromtimestamp(int(expiration_date))
        else:
            self.expiration_date = None

        self.revoked, self.disabled, self.expired = [False] * 3

        if 'r' in flags:
            self.revoked = True
        if 'd' in flags:
            self.disabled = True
        if 'e' in flags:
            self.expired = True

    def __repr__(self):
        return 'Identity %s' % self.uid

    def __str__(self):
        return repr(self)


class KeyServer(object):
    """
    Keyserver object used for search queries.
    """

    def __init__(self, host, port=11371):
        self.host = host
        self.port = port

    def __parse_index(self, response):
        """
        Parse machine readable index response.
        """
        lines = response.splitlines()[1:]
        result, key = [], None

        for line in iter(lines):
            items = line.split(':')
            if items[0] == 'pub':
                key = Key(self.host, self.port, *items[1:])
                result.append(key)
            if items[0] == 'uid' and key:
                key.identities.append(Identity(*items[1:]))

        return result

    def search(self, query, exact=False, nm=False):
        """
        Searches for given query, returns list of key objects.
        """
        opts = (
            ('mr', True), ('nm', nm),
        )

        params = urllib.urlencode({
            'search': query,
            'op': 'index',
            'options': ','.join(name for name, val in opts if val),
            'exact': exact and 'on' or 'off',
        })

        request_url = '%s:%d/pks/lookup?%s' % (self.host, self.port, params)
        response = urllib2.urlopen(request_url).read()
        return self.__parse_index(response)

    def add(self, key):
        """
        Upload key to the keyserver.
        """
        request_url = '%s:%d/pks/add' % (self.host, self.port)
        params = urllib.urlencode({'keytext': key})
        urllib2.urlopen(request_url, params)
