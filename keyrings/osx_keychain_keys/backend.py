# -*- coding: utf-8 -*-
__all__ = ['OSXKeychainKeyType', 'OSXKeyChainKeyClassType', 'OSXKeychainKeysBackend']

import distutils.util
import os
from enum import Enum
from typing import Optional, Union

# noinspection PyUnresolvedReferences
from CoreFoundation import (
    CFDictionaryCreateMutable,
    kCFAllocatorDefault,
    CFDictionarySetValue,
    CFRelease,
    CFMutableDictionaryRef,
)

# noinspection PyUnresolvedReferences
from Security import (
    kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyTypeRSA,
    kSecAttrKeyTypeDSA,
    kSecAttrKeyTypeAES,
    kSecAttrKeyTypeDES,
    kSecAttrKeyType3DES,
    kSecAttrKeyTypeRC4,
    kSecAttrKeyTypeRC2,
    kSecAttrKeyTypeCAST,
    kSecAttrKeyTypeECDSA,
    kSecAttrKeyTypeEC,
    kSecClass,
    kSecClassKey,
    kSecAttrIsPermanent,
    SecKeyCreateRandomKey,
    kSecAttrKeyType,
    kSecAttrKeySizeInBits,
    kSecAttrSynchronizable,
    kSecAttrLabel,
    kSecAttrApplicationTag,
    kSecPrivateKeyAttrs,
    kSecAttrAccessControl,
    kSecUseDataProtectionKeychain,
    kSecAccessControlPrivateKeyUsage,
    kSecAttrTokenIDSecureEnclave,
    kSecAttrTokenID,
    kSecAttrAccessGroup,
    SecAccessControlCreateWithFlags,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlRef,
    kSecAttrKeyClassPrivate,
    kSecAttrKeyClassPublic,
    kSecAttrKeyClassSymmetric,
    SecItemAdd,
    SecKeyRef,
    kSecAttrKeyClass,
    SecItemImport,
    SecItemImportExportKeyParameters,
    kSecValueRef,
    SecItemExport,
    kSecAttrIsExtractable,
    kSecFormatOpenSSL,
    kSecAttrIsSensitive,
    SecItemCopyMatching,
    kSecMatchLimit,
    kSecMatchLimitAll,
    kSecReturnRef,
    SecItemDelete,
    SecKeyCopyPublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from keyring.backends.OS_X import Keyring
from keyring.errors import PasswordSetError, KeyringError, PasswordDeleteError
from keyring.util import properties


class OSXKeychainKeyType(Enum):
    """
    Represents the kSecAttrKeyType* enum values.

    Each value yields a different key-type (e.g. RSA, EC, 3DES, ...)
    """

    ECSecPrimeRandom = kSecAttrKeyTypeECSECPrimeRandom
    RSA = kSecAttrKeyTypeRSA
    DSA = kSecAttrKeyTypeDSA  # Can only be imported, not generated
    AES = kSecAttrKeyTypeAES  # Can only be imported, not generated
    DES = kSecAttrKeyTypeDES  # Can only be imported, not generated
    TripleDES = kSecAttrKeyType3DES  # Can only be imported, not generated
    RC4 = kSecAttrKeyTypeRC4  # Can only be imported, not generated
    RC2 = kSecAttrKeyTypeRC2  # Can only be imported, not generated
    CAST = kSecAttrKeyTypeCAST  # Can only be imported, not generated
    ECDSA = kSecAttrKeyTypeECDSA  # Equivalent to ECSecPrimeRandom
    EC = kSecAttrKeyTypeEC  # Equivalent to ECSecPrimeRandom


class OSXKeyChainKeyClassType(Enum):
    """
    Represents the kSecAttrKeyClass* enum values.

    Public    = Public key.
    Private   = Private key.
    Symmetric = Private key for symmetric encryptions.
    """

    Public = kSecAttrKeyClassPublic
    Private = kSecAttrKeyClassPrivate
    Symmetric = kSecAttrKeyClassSymmetric


class OSXKeychainKeysBackend(Keyring):
    """
    This keyring backend saves public, private keys or certificates to as keychain key-items.
    It supports saving existing keys, or generating keys for the caller (given an empty password).

    Setting the following is supported, via the KEYRING_PROPERTY_<prop> environment variables:

    KEYRING_PROPERTY_KEY_TYPE:              One of OSXKeychainKeyType.

    KEYRING_PROPERTY_KEY_SIZE_IN_BITS:      Imported, or generated key-size.

    KEYRING_PROPERTY_IS_PERMANENT:          Only relevant for key generation - not importing, on import a key is always
    permanent. If set, the key is stored in the keyring / enclave; if not - a temp key is provided.

    KEYRING_PROPERTY_USE_SECURE_ENCLAVE:    If set, will use store the key in the secure enclave (TPM-equivalent) -
    requires the executing binary (python interpreter) to be code signed with specific Apple entitlements.

    KEYRING_PROPERTY_ACCESS_GROUP:          If set, will set the kSecAttrAccessGroup attribute to this value.
    Requires using the secure enclave.

    KEYRING_PROPERTY_KEY_PASSWORD:          Only relevant when importing (not generating) keys, when set, this is
    the passphrase of the imported key; Only supports DES and 3DES encrypted keys - AES and camellia are not supported.

    KEYRING_PROPERTY_KEY_CLASS_TYPE:        One of OSXKeyChainKeyClassType enum values, only relevant for imported keys.

    KEYRING_PROPERTY_IS_EXTRACTABLE:        If set, one will be able to retrieve the key value back; If not, the key
    can only be operated against with native encryption / signing primitives.
    """

    DEFAULT_KEY_TYPE = OSXKeychainKeyType.ECSecPrimeRandom
    DEFAULT_IS_PERMANENT = True
    DEFAULT_USE_SECURE_ENCLAVE = False
    DEFAULT_IS_EXTRACTABLE = True

    DEFAULT_KEY_SIZE_PER_KEY_TYPE = {
        OSXKeychainKeyType.ECSecPrimeRandom.value: 256,
        OSXKeychainKeyType.RSA.value: 4096,
        OSXKeychainKeyType.DSA.value: 2048,
        OSXKeychainKeyType.AES.value: 256,
        OSXKeychainKeyType.DES.value: 56,
        OSXKeychainKeyType.TripleDES.value: 168,
        OSXKeychainKeyType.RC4.value: 2048,
        OSXKeychainKeyType.RC2.value: 1024,
        OSXKeychainKeyType.CAST.value: 128,
        OSXKeychainKeyType.ECDSA.value: 256,
        OSXKeychainKeyType.EC.value: 256,
    }

    DEFAULT_KEY_CLASS_TYPE_PER_KEY_TYPE = {
        OSXKeychainKeyType.ECSecPrimeRandom.value: OSXKeyChainKeyClassType.Private.value,
        OSXKeychainKeyType.RSA.value: OSXKeyChainKeyClassType.Private.value,
        OSXKeychainKeyType.DSA.value: OSXKeyChainKeyClassType.Private.value,
        OSXKeychainKeyType.AES.value: OSXKeyChainKeyClassType.Symmetric.value,
        OSXKeychainKeyType.DES.value: OSXKeyChainKeyClassType.Symmetric.value,
        OSXKeychainKeyType.TripleDES.value: OSXKeyChainKeyClassType.Symmetric.value,
        OSXKeychainKeyType.RC4.value: OSXKeyChainKeyClassType.Symmetric.value,
        OSXKeychainKeyType.RC2.value: OSXKeyChainKeyClassType.Symmetric.value,
        OSXKeychainKeyType.CAST.value: OSXKeyChainKeyClassType.Symmetric.value,
        OSXKeychainKeyType.ECDSA.value: OSXKeyChainKeyClassType.Private.value,
        OSXKeychainKeyType.EC.value: OSXKeyChainKeyClassType.Private.value,
    }

    def __init__(
        self,
        key_type: Optional[OSXKeychainKeyType] = None,
        key_class_type: Optional[OSXKeyChainKeyClassType] = None,
        key_size_in_bits: Optional[int] = None,
        is_permanent: Optional[bool] = None,
        use_secure_enclave: Optional[bool] = None,
        access_group: Optional[str] = None,
        is_extractable: Optional[bool] = None,
    ):
        """

        :param key_type: One of OSXKeychainKeyType key types.
        :param key_class_type: One of OSKeyChainKeyClassType types.
        :param key_size_in_bits: Key size.
        :param is_permanent: If set, will store the secret in the keyring / enclave; If not - will return a temp key.
        :param use_secure_enclave: If set, will store the key in the secure enclave (requires code-signed executable)
        :param access_group: If set, will limit management of this key to this access group (required code-signed
                             executable); requires using the secure enclave.
        :param is_extractable: If set, the inserted key will be extractable (meaning, one can get the key back)
                               If not, one can only use encryption primitives against the key.
        """

        self.key_type = key_type
        self.key_class_type = key_class_type
        self.key_size_in_bits = key_size_in_bits
        self.is_permanent = is_permanent
        self.use_secure_enclave = use_secure_enclave
        self.access_group = access_group
        self.is_extractable = is_extractable

        self.key_password = None
        self.set_properties_from_env()

    # noinspection PyNestedDecorators
    @properties.ClassProperty
    @classmethod
    def priority(cls) -> int:
        return super(OSXKeychainKeysBackend, cls).priority - 1

    def set_password(
        self, service: str, username: str, password: Union[str, bytes, None]
    ):
        """
        Inserts the given key to keychain, or generates a new one if password is blank.
        Key generation is only supported for RSA & Elliptic-Curve assymetric keys, due to keychain's API limitations.
        Meaning, DSA and symmetric keys are not supported for generation - only for existing key import.

        :param service: Will be used as the kSecAttrLabel attribute.
        :param username: Will be used as the kSecAttrApplicationTag attribute.
        :param password: If blank, a key is generated, if non-blank - should be either a path to a key-file,
                         or key-data, encoded in some known format (e.g. PEM).
        :return: A reference to a python-wrapped private or public key, if is_extractable is set; else, None.
        """
        assert isinstance(
            service, str
        ), f'Expected service to be of type str, but got: {type(service)}'
        assert isinstance(
            username, str
        ), f'Expected username to be of type str, but got: {type(username)}'
        assert isinstance(password, (str, bytes, type(None))), (
            'Expected password to be one of: str, bytes, None, '
            f'but got: {type(password)}'
        )

        params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, None, None)
        private_key_params = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, None, None
        )
        access_control = self._get_access_control()
        try:
            self._populate_private_key_params(
                private_key_params, service, username, access_control
            )
            self._populate_key_params(params, private_key_params, password)

            if password:
                error, key = SecItemAdd(params, None)
                key = key[-1] if key else key
            elif self.key_class_type == OSXKeychainKeyType.DSA:
                raise PasswordSetError(
                    'Generating asymmetric keys is only supported for RSA and Elliptic-Curve algorithms'
                )
            elif self.key_class_type == OSXKeyChainKeyClassType.Symmetric.value:
                raise PasswordSetError(
                    'Generating symmetric keys is not supported by the keychain API'
                )
            else:
                key, error = SecKeyCreateRandomKey(params, None)
                if key and self.key_class_type == OSXKeyChainKeyClassType.Public.value:
                    key = SecKeyCopyPublicKey(key)

            if error or not key:
                raise PasswordSetError(f'Failed creating private key: {error}')

            if self.is_extractable:
                return self._pythonify_key(key)
        finally:
            if access_control:
                CFRelease(access_control)
            CFRelease(private_key_params)
            CFRelease(params)

    def _get_access_control(self) -> Optional[SecAccessControlRef]:
        # Do note: Using access control, or the secure enclave, requires the executing binary (i.e. python interpreter)
        # to be code signed with specific apple entitlements.
        if not self.use_secure_enclave:
            return None

        access_control, error = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage,
            None,
        )
        if error or not access_control:
            raise KeyringError(f'Failed in SecAccessControlCreateWithFlags: {error}')

        return access_control

    def _populate_private_key_params(
        self,
        private_key_params: CFMutableDictionaryRef,
        service: str,
        username: str,
        access_control: Optional[SecAccessControlRef] = None,
    ):
        CFDictionarySetValue(private_key_params, kSecClass, kSecClassKey)

        if access_control:
            CFDictionarySetValue(
                private_key_params, kSecAttrAccessControl, access_control
            )

        CFDictionarySetValue(private_key_params, kSecAttrLabel, service)
        CFDictionarySetValue(private_key_params, kSecAttrIsPermanent, self.is_permanent)
        CFDictionarySetValue(
            private_key_params, kSecAttrApplicationTag, username.encode('utf-8')
        )

    def _populate_key_params(
        self,
        params: CFMutableDictionaryRef,
        private_key_params: CFMutableDictionaryRef,
        password: Union[str, bytes, None],
    ):
        # Keys can't be synchronized using iCloud
        CFDictionarySetValue(params, kSecAttrSynchronizable, False)

        if self.use_secure_enclave:
            CFDictionarySetValue(
                params, kSecUseDataProtectionKeychain, self.use_secure_enclave
            )
            CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)

            if self.access_group:
                CFDictionarySetValue(params, kSecAttrAccessGroup, self.access_group)

        CFDictionarySetValue(params, kSecAttrIsExtractable, self.is_extractable)
        CFDictionarySetValue(params, kSecAttrIsSensitive, self.is_sensitive)

        CFDictionarySetValue(params, kSecAttrKeyType, self.key_type)
        CFDictionarySetValue(params, kSecAttrKeyClass, self.key_class_type)
        CFDictionarySetValue(params, kSecAttrKeySizeInBits, self.key_size_in_bits)

        if password:
            key_ref = self._get_sec_key_from_password(password)
            CFDictionarySetValue(params, kSecValueRef, key_ref)
            params.addEntriesFromDictionary_(private_key_params)
            return

        CFDictionarySetValue(params, kSecPrivateKeyAttrs, private_key_params)

    def _get_sec_key_from_password(self, password: Union[str, bytes]):
        if os.path.isfile(password):
            with open(password, 'rb') as f:
                password = f.read()

        key_params = SecItemImportExportKeyParameters(
            keyAttributes=(kSecAttrIsExtractable,), passphrase=self.key_password
        )
        error, input_format, item_type, out_items = SecItemImport(
            password,
            None,  # fileNameOrExtension
            None,  # inputFormat
            None,  # itemType
            0,  # flags
            key_params,  # keyParameters
            None,  # keychain
            None,  # outItems
        )

        if error or not out_items:
            raise KeyringError(f'Error calling SecItemImport: {error}')

        return out_items[-1]

    def get_password(self, service: Optional[str], username: Optional[str]):
        """
        Returns all keyring / enclave keys matching kSecAttrLabel = service and kSecAttrApplicationTag = username,
        python-wrapped.
        If a single key is matched, the result is a list of size 1.

        :param service: If set, will lookup the key with kSecAttrLabel = service
        :param username: If set, will lookup the key with kSecAttrApplicationTag = username
        :return: A python-wrapped private / public key of the key.
        """
        query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, None, None)
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll)
        CFDictionarySetValue(query, kSecReturnRef, 1)

        if service:
            CFDictionarySetValue(query, kSecAttrLabel, service)

        if username:
            CFDictionarySetValue(
                query, kSecAttrApplicationTag, username.encode('utf-8')
            )

        if self.access_group:
            CFDictionarySetValue(query, kSecAttrAccessGroup, self.access_group)

        error, res = SecItemCopyMatching(query, None)
        if error:
            raise KeyringError(f'Error calling SecItemCopyMatching: {error}')

        return [self._pythonify_key(key) for key in res]

    def delete_password(self, service: str, username: str) -> None:
        """
        Deletes the keyring / enclave key with kSecAttrLabel = service and kSecAttrApplicationTag = username.
        Beware: If more than one key matches the query, this will delete all matched keys.

        :param service: If set, will lookup the key with kSecAttrLabel = service
        :param username: If set, will lookup the key with kSecAttrApplicationTag = username
        """
        query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, None, None)
        CFDictionarySetValue(query, kSecClass, kSecClassKey)

        if service:
            CFDictionarySetValue(query, kSecAttrLabel, service)

        if username:
            CFDictionarySetValue(
                query, kSecAttrApplicationTag, username.encode('utf-8')
            )

        if self.access_group:
            CFDictionarySetValue(query, kSecAttrAccessGroup, self.access_group)

        error = SecItemDelete(query)
        if error:
            raise PasswordDeleteError(f'Error calling SecItemDelete: {error}')

    def _pythonify_key(self, key: SecKeyRef):
        assert isinstance(
            key, SecKeyRef
        ), f'Expected key to be of type SecKeyRef, but got: {type(key)}'

        error, der_key = SecItemExport(
            key,
            kSecFormatOpenSSL,  # outputFormat - OpenSSL == DER
            0,  # flags
            None,  # keyParams
            None,  # exportedData
        )

        if error or not der_key:
            raise KeyringError(f'Error calling SecItemExport: {error}')

        if self.key_class_type in [
            OSXKeyChainKeyClassType.Private.value,
            OSXKeyChainKeyClassType.Symmetric.value,
        ]:
            return serialization.load_der_private_key(
                der_key, password=None, backend=default_backend()
            )

        return serialization.load_der_public_key(der_key, default_backend())

    @property
    def key_type(self) -> str:
        return self._key_type

    @key_type.setter
    def key_type(self, key_type: Union[str, OSXKeychainKeyType, None]) -> None:
        assert isinstance(
            key_type, (str, OSXKeychainKeyType, type(None))
        ), f'Expected key_type type to be one of str, OSXKeychainKeyType, None, but got: {type(key_type)}'

        if key_type is None:
            self._key_type = self.DEFAULT_KEY_TYPE.value
            return

        if isinstance(key_type, OSXKeychainKeyType):
            self._key_type = key_type.value
            return

        self._key_type = str(key_type)

    @property
    def key_size_in_bits(self) -> int:
        return self._key_size_in_bits

    @key_size_in_bits.setter
    def key_size_in_bits(self, key_size_in_bits: Union[int, str, None]) -> None:
        assert isinstance(
            key_size_in_bits, (int, str, type(None))
        ), f'Expected key_size_in_bits type to be one of int, str, None, but got: {type(key_size_in_bits)}'

        if key_size_in_bits is None:
            self._key_size_in_bits = self.DEFAULT_KEY_SIZE_PER_KEY_TYPE[self.key_type]
            return

        self._key_size_in_bits = int(key_size_in_bits)

    @property
    def is_permanent(self) -> bool:
        # noinspection PyUnresolvedReferences
        return self._is_permanent

    @is_permanent.setter
    def is_permanent(self, is_permanent: Union[bool, str, None]):
        self._set_bool_attr('is_permanent', is_permanent, self.DEFAULT_IS_PERMANENT)

    @property
    def use_secure_enclave(self) -> bool:
        # noinspection PyUnresolvedReferences
        return self._use_secure_enclave

    @use_secure_enclave.setter
    def use_secure_enclave(self, use_secure_enclave):
        self._set_bool_attr(
            'use_secure_enclave', use_secure_enclave, self.DEFAULT_USE_SECURE_ENCLAVE
        )

    @property
    def access_group(self) -> Optional[str]:
        return self._access_group

    @access_group.setter
    def access_group(self, access_group: Optional[str]):
        assert isinstance(
            access_group, (str, type(None))
        ), f'Expected access_group type to be one of str, None, but got: {type(access_group)}'

        self._access_group = access_group

    @property
    def key_class_type(self) -> Optional[str]:
        return self._key_class_type

    @key_class_type.setter
    def key_class_type(self, key_class_type: Union[OSXKeyChainKeyClassType, str, None]):
        assert isinstance(key_class_type, (OSXKeyChainKeyClassType, str, type(None))), (
            'Expected key_class_type type to be one of OSXKeyChainKeyClassType, str, None, but got: '
            f'{type(key_class_type)}'
        )

        if key_class_type is None:
            self._key_class_type = self.DEFAULT_KEY_CLASS_TYPE_PER_KEY_TYPE[
                self.key_type
            ]
            return

        if isinstance(key_class_type, OSXKeyChainKeyClassType):
            self._key_class_type = key_class_type.value
            return

        self._key_class_type = str(key_class_type)

    @property
    def key_password(self) -> Optional[bytes]:
        return self._key_password

    @key_password.setter
    def key_password(self, key_password: Optional[str]):
        assert isinstance(
            key_password, (str, bytes, type(None))
        ), f'Expected key_password type to be one of str, bytes, None, but got: {type(key_password)}'

        if isinstance(key_password, str):
            self._key_password = key_password.encode('utf-8')
        else:
            self._key_password = key_password

    @property
    def is_sensitive(self) -> bool:
        return self.key_class_type in [
            OSXKeyChainKeyClassType.Private.value,
            OSXKeyChainKeyClassType.Symmetric.value,
        ]

    @property
    def is_extractable(self) -> bool:
        # noinspection PyUnresolvedReferences
        return self._is_extractable

    @is_extractable.setter
    def is_extractable(self, is_extractable):
        self._set_bool_attr(
            'is_extractable', is_extractable, self.DEFAULT_IS_EXTRACTABLE
        )

    def _set_bool_attr(
        self, attr_name: str, attr_value: Union[bool, str, None], default_value: bool
    ):
        assert isinstance(
            attr_value, (bool, str, type(None))
        ), f'Expected f{attr_name} type to be one of bool, str, None, but got: {type(attr_value)}'

        attr_name = f'_{attr_name}'
        if attr_value is None:
            setattr(self, attr_name, default_value)
            return

        if isinstance(attr_value, str):
            setattr(self, attr_name, bool(distutils.util.strtobool(attr_value)))
            return

        setattr(self, attr_name, attr_value)
