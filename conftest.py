import platform

collect_ignore = []

if platform.system() != 'Darwin':
    collect_ignore.append('keyrings/osx_keychain_keys/tests/test_keychain_keys.py')
