from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from keyrings.osx_keychain_keys.backend import (
    OSXKeychainKeysBackend,
    OSXKeychainKeyType,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def backend_example():
    backend = OSXKeychainKeysBackend(
        key_type=OSXKeychainKeyType.RSA,
        key_size_in_bits=4096,
        is_permanent=True,
        use_secure_enclave=False,
        access_group=None,
        is_extractable=True,
    )

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )

    # noinspection PyTypeChecker
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key = backend.set_password(service='pasten.com', username='dany74q', password=pem)
    assert isinstance(key, RSAPrivateKey)

    matching_keys = backend.get_password(service='pasten.com', username='dany74q')
    assert len(matching_keys) == 1
    assert isinstance(matching_keys[0], RSAPrivateKey)

    backend.delete_password(service='pasten.com', username='dany74q')


if __name__ == '__main__':
    backend_example()
