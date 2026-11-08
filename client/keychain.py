"""Local macOS Keychain generic passwords. Keys never enter command arguments."""

import ctypes as c
import secrets
import sys
from functools import lru_cache

SERVICE = b"org.crytosage.storage"
NOT_FOUND = -25300
DUPLICATE = -25299


@lru_cache(maxsize=1)
def _security():
    if sys.platform != "darwin":
        raise ValueError("macOS Keychain is unavailable on this platform")
    api = c.CDLL("/System/Library/Frameworks/Security.framework/Security")
    api.SecKeychainFindGenericPassword.argtypes = [
        c.c_void_p,
        c.c_uint32,
        c.c_char_p,
        c.c_uint32,
        c.c_char_p,
        c.POINTER(c.c_uint32),
        c.POINTER(c.c_void_p),
        c.c_void_p,
    ]
    api.SecKeychainAddGenericPassword.argtypes = [
        c.c_void_p,
        c.c_uint32,
        c.c_char_p,
        c.c_uint32,
        c.c_char_p,
        c.c_uint32,
        c.c_char_p,
        c.c_void_p,
    ]
    api.SecKeychainItemFreeContent.argtypes = [c.c_void_p, c.c_void_p]
    return api


def master_key(
    account: str, *, create: bool = False, migrate: bytes | None = None
) -> bytes:
    api = _security()
    identifier = account.encode("ascii")
    item = (None, len(SERVICE), SERVICE, len(identifier), identifier)

    def read():
        size, data = c.c_uint32(), c.c_void_p()
        status = api.SecKeychainFindGenericPassword(
            *item, c.byref(size), c.byref(data), None
        )
        if status == NOT_FOUND:
            return None
        if status:
            raise ValueError(f"Cannot read the macOS Keychain item (status {status})")
        try:
            if size.value != 32:
                raise ValueError("Invalid macOS Keychain master key length")
            return c.string_at(data, size.value)
        finally:
            api.SecKeychainItemFreeContent(None, data)

    key = read()
    if key is None and (create or migrate is not None):
        candidate = migrate if migrate is not None else secrets.token_bytes(32)
        status = api.SecKeychainAddGenericPassword(
            *item, len(candidate), candidate, None
        )
        if status not in (0, DUPLICATE):
            raise ValueError(f"Cannot create the macOS Keychain item (status {status})")
        key = read()
    if key is None:
        raise ValueError(
            "macOS Keychain master key is missing; restore the original key"
        )
    if migrate is not None and not secrets.compare_digest(key, migrate):
        raise ValueError("Existing Keychain item differs from the filesystem key")
    return key
