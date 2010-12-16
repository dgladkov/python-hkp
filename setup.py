"""
Python HKP procol client implementation based on the
`current draft spec <http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00>`_.
"""

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='python-hkp',
    version='0.1.2',
    url='https://github.com/dgladkov/python-hkp/',
    license='BSD',
    author='Dmitry Gladkov',
    author_email='dmitry.gladkov@gmail.com',
    description='Python HKP client',
    long_description=__doc__,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    packages=['hkp'],
    platforms='any'
)