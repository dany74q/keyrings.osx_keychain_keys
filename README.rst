.. image:: https://img.shields.io/pypi/v/keyrings.osx_keychain_keys.svg
   :target: https://pypi.org/project/keyrings.osx-keychain-keys
   :alt: PyPi version

.. image:: https://img.shields.io/pypi/pyversions/keyrings.osx_keychain_keys.svg
   :alt: Python version

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/psf/black
   :alt: Code style: Black

.. image:: https://readthedocs.org/projects/keyringsosx_keychain_keys/badge/?version=latest
   :target: https://keyringsosx_keychain_keys.readthedocs.io/en/latest/?badge=latest
   :alt: Read the docs

.. image:: https://img.shields.io/github/workflow/status/dany74q/keyrings.osx_keychain_keys/CI
   :alt: CI workflow

|

This library is a backend addon for `keyring <https://github.com/jaraco/keyring>`_, it provides a backend that manages
OSX keychain key-class items.


Supported features:

* Auto-generating keys via ``SecKeyCreateRandomKey``
* Importing existing keys of various formats via ``SecItemAdd``
* Storing keys in keychain, or generating transient keys
* Storing keys in the secure enclave (T2 chip - 'TPM'); for code-signed interpreters
* Limiting key management to specific access groups; for code-signed interpreters
* Making keys non-extractable, so that the key content could not be retrieved, but only used for signing or encryption

Using This Backend
==================

One can utilize this backend both programatically, or from the CLI.

.. code-block:: python

    import keyring
    from keyrings.osx_keychain_keys.backend import OSXKeychainKeysBackend, OSXKeychainKeyType, OSXKeyChainKeyClassType

    backend = OSXKeychainKeysBackend(
        key_type=OSXKeychainKeyType.RSA, # Key type, e.g. RSA, RC, DSA, ...
        key_class_type=OSXKeyChainKeyClassType.Private, # Private key, Public key, Symmetric-key
        key_size_in_bits=4096,
        is_permanent=True, # If set, saves the key in keychain; else, returns a transient key
        use_secure_enclave=False, # Saves the key in the T2 (TPM) chip, requires a code-signed interpreter
        access_group=None, # Limits key management and retrieval to set group, requires a code-signed interpreter
        is_extractable=True # If set, private key is extractable; else, it can't be retrieved, but only operated against
    )

    keyring.set_keyring(backend)

    # If password is not set - a key is generated
    keyring.set_password('some-label', 'some-tag', password=None)

    # If password is set - it could be a file path to a key to import to keychain
    keyring.set_password('some-label', 'some-tag', '/tmp/my-private.key')
    # It could also be the key-data itself
    keyring.set_password('some-label', 'some-tag', '-----BEGIN RSA PRIVATE KEY----\n....')

    # Returns a python-wrapped (using hazmat cryptography lib) private / public key
    keyring.get_password('some-label', 'some-tag')

    # Deletes a key from keychain
    keyring.delete_password('some-label', 'some-tag')


See more examples in ``keyrings/osx_keychain_keys/examples`` and ``keyrings/osx_keychain_keys/tests``.

Command-line Utility
--------------------

One can also use the keyring CLI to operate against this backend::

    $ keyring -b keyrings.osx_keychain_keys.backend.OSXKeychainKeysBackend set "some-label" "some-tag"

Security Considerations
=======================

Using mac's keychain has some caveats that should be noted, namely:

* Some keychain APIs require the invoking application (the python interpreter, in this case) to be code-signed with
  specific Apple entitlements, namely:

  * Saving the key to the secure enclave (T2 / TPM chip)
  * Limiting access via access controls (i.e. requiring touch-id / password before key retrieval)
  * Limiting key management to specific access groups

* By default, all inserted keys are accessible to the runnable executable, meaning
  the interpreter you use can manage the generated or imported keys.

  If you use a virtualenv, you may create one with ``$> venv --copies`` to limit accessibility to the specific venv
  python binary.

Making Releases
===============

A CI/CD pipeline is setup on github - once a PR is merged to master, a pre-release
will be automatically deployed to github;
When a release is tagged, it will be automatically deployed to pypi.

Running Tests
=============

To run the tests locally (a darwin machine is required), install and invoke
`tox <https://pypi.org/project/tox>`_.
