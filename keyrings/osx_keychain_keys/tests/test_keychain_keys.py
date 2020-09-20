import os
import platform
import unittest
from uuid import uuid4

# noinspection PyUnresolvedReferences
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from keyring.errors import PasswordSetError, KeyringError

from keyrings.osx_keychain_keys.backend import (
    OSXKeychainKeysBackend,
    OSXKeychainKeyType,
    OSXKeyChainKeyClassType,
)


def is_keychain_keys_supported():
    return platform.system() == 'Darwin'


@unittest.skipUnless(is_keychain_keys_supported(), "Only supported in Darwin machines")
class KeychainKeyringBackendTests(unittest.TestCase):
    def test_key_types_generation(self):
        for key_type in OSXKeychainKeyType:
            backend = OSXKeychainKeysBackend(key_type=key_type, is_permanent=False)

            if (
                backend.key_class_type == OSXKeyChainKeyClassType.Symmetric.value
                or backend.key_type == OSXKeychainKeyType.DSA.value
            ):
                with self.assertRaises(PasswordSetError):
                    backend.set_password(
                        service="pasten.com", username="dany74q", password=None
                    )
            else:
                res = backend.set_password(
                    service="pasten.com", username="dany74q", password=None
                )
                self.assertIsNotNone(res, 'Expected a key object, but got None')

    def test_key_class_types_generation(self):
        backend = OSXKeychainKeysBackend(
            key_type=OSXKeychainKeyType.RSA,
            key_class_type=OSXKeyChainKeyClassType.Private,
            is_permanent=False,
        )
        res = backend.set_password(
            service='pasten.com', username='dany74q', password=None
        )
        self.assertIsNotNone(res, 'Expected a private key object, but got None')
        self.assertIsInstance(
            res,
            RSAPrivateKey,
            f'Expected an instance of RSAPrivateKey, but got: {type(res)}',
        )

        backend = OSXKeychainKeysBackend(
            key_type=OSXKeychainKeyType.RSA,
            key_class_type=OSXKeyChainKeyClassType.Public,
            is_permanent=False,
        )
        res = backend.set_password(
            service='pasten.com', username='dany74q', password=None
        )
        self.assertIsNotNone(res, 'Expected a public key object, but got None')
        self.assertIsInstance(
            res,
            RSAPublicKey,
            f'Expected an instance of RSAPublicKey, but got: {type(res)}',
        )

    def test_key_sizes(self):
        for key_size_in_bits in [1024, 2048, 4096]:
            backend = OSXKeychainKeysBackend(
                key_type=OSXKeychainKeyType.RSA,
                key_size_in_bits=key_size_in_bits,
                is_permanent=False,
            )
            res = backend.set_password(
                service='pasten.com', username='dany74q', password=None
            )
            self.assertIsNotNone(res, 'Expected a private key object, but got None')
            self.assertIsInstance(
                res,
                RSAPrivateKey,
                f'Expected an instance of RSAPrivateKey, but got: {type(res)}',
            )
            self.assertEqual(res.key_size, key_size_in_bits)

    def test_key_permanence(self):
        backend = OSXKeychainKeysBackend(
            key_type=OSXKeychainKeyType.RSA, is_permanent=True
        )
        service, username = str(uuid4()), 'dany74q'
        backend.set_password(service=service, username=username, password=None)
        try:
            res = backend.get_password(service=service, username=username)
            self.assertIsNotNone(res, 'Expected a result for permanent-stored key')
        finally:
            backend.delete_password(service=service, username=username)

    def test_transient_key_not_saved_in_keychain(self):
        backend = OSXKeychainKeysBackend(
            key_type=OSXKeychainKeyType.RSA, is_permanent=False
        )
        service, username = str(uuid4()), 'dany74q'
        backend.set_password(service=service, username=username, password=None)
        with self.assertRaises(KeyringError):
            backend.get_password(service=service, username=username)

    def test_non_extractable_keys_cant_be_retrieved(self):
        backend = OSXKeychainKeysBackend(
            key_type=OSXKeychainKeyType.RSA, is_permanent=True, is_extractable=False
        )
        service, username = str(uuid4()), 'dany74q'
        res = backend.set_password(service=service, username=username, password=None)
        try:
            self.assertIsNone(
                res,
                f'Expected None result when is_extractable is False, but got: {res}',
            )
            with self.assertRaises(KeyringError):
                # We should not be able to retrieve the data of non-extractable keys
                backend.get_password(service=service, username=username)
        finally:
            backend.delete_password(service=service, username=username)

    def test_key_passphrase(self):
        backend = OSXKeychainKeysBackend(key_type=OSXKeychainKeyType.RSA)
        service, username = str(uuid4()), 'dany74q'
        backend.key_password = 'pasten1!'

        current_dir = os.path.dirname(__file__)

        with open(os.path.join(current_dir, 'des_encrypted.key'), 'rb') as f:
            des_encrypted_key = f.read()
            backend.set_password(
                service=service, username=username, password=des_encrypted_key
            )
            backend.delete_password(service=service, username=username)

        with open(os.path.join(current_dir, '3des_encrypted.key'), 'rb') as f:
            triple_des_encrypted_key = f.read()
            backend.set_password(
                service=service, username=username, password=triple_des_encrypted_key
            )
            backend.delete_password(service=service, username=username)

        # Non DES encryptions are not supported
        with open(os.path.join(current_dir, 'aes_128_encrypted.key'), 'rb') as f:
            aes_encrypted_key = f.read()
            with self.assertRaises(KeyringError):
                backend.set_password(
                    service=service, username=username, password=aes_encrypted_key
                )
