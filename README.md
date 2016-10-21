# Python HPK (PGP keyserver) client

## Install

```bash
pip install python-hkp
```

### Usage example:

```python
>>> from hkp import KeyServer
>>> serv = KeyServer('http://pool.sks-keyservers.net')
>>> serv.search('Dmitry Gladkov')
[Key 28DFA7EC RSA (Encrypt or Sign), Key 473C57D9 RSA (Encrypt or Sign)]
>>> serv.search('Dmitry Gladkov')[0].identities
[Identity Dmitry Gladkov (dgl) <dmitry.gladkov@gmail.com>]
```
