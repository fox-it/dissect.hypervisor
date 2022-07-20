# Reference:
# - crypto-util
# - libvmlibs.so
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Dict, List
from urllib.parse import unquote


try:
    import _pystandalone

    HAS_PYSTANDALONE = True
except ImportError:
    HAS_PYSTANDALONE = False

try:
    from Crypto.Cipher import AES

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


CIPHER_KEY_SIZES = {
    "AES-256": 32,
    "AES-192": 24,
    "AES-128": 16,
}

HMAC_MAP = {
    "HMAC-SHA-1": ("sha1", 20),
    "HMAC-SHA-1-128": ("sha1", 16),
    "HMAC-SHA-256": ("sha256", 32),
}

PASS2KEY_MAP = {
    "PBKDF2-HMAC-SHA-1": "sha1",
    "PBKDF2-HMAC-SHA-256": "sha256",
}


class VMX:
    def __init__(self, vm_settings: Dict[str, str]):
        self.attr = vm_settings

    @classmethod
    def parse(cls, string: str) -> VMX:
        """Parse a VMX dictionary from a string."""
        return cls(_parse_dictionary(string))

    @property
    def encrypted(self) -> bool:
        """Return whether this VMX is encrypted.

        Encrypted VMXs will have both a `encryption.keySafe` and `encryption.data` value.
        The `encryption.keySafe` is a string encoded `KeySafe`, which is made up of key locators.

        For example:
            vmware:key/list/(pair/(phrase/phrase_id/phrase_content,hmac,data),pair/(.../...,...,...))

        A KeySafe must be a list of Pairs. Each Pair has a wrapped key, an HMAC type and some encrypted data.
        It's implementation specific how to unwrap a key. E.g. a phrase is just PBKDF2. The unwrapped key
        can be used to unlock the encrypted Pair data. This will contain the final encryption key to decrypt
        the data in `encryption.data`.

        So, in summary, to unseal a KeySafe:
        Parse KeySafe -> iterate pairs -> unlock Pair -> unwrap key (e.g. Phrase) -> decrypt Pair data -> parse dict

        The terms for unwrapping, unlocking and unsealing are taken from VMware.
        """
        return "encryption.keysafe" in self.attr

    def unlock_with_phrase(self, passphrase: str) -> None:
        """Unlock this VMX in-place with a passphrase if it's encrypted.

        This will load the KeySafe from the current dictionary and attempt to recover the encryption key
        from it using the given passphrase. This key is used to decrypt the encrypted VMX data.

        The dictionary is updated in-place with the encrypted VMX data.
        """
        if not self.encrypted:
            raise TypeError("VMX is not encrypted")

        safe = KeySafe.from_text(self.attr["encryption.keysafe"])
        key, mac = safe.unseal_with_phrase(passphrase)

        encrypted = base64.b64decode(self.attr["encryption.data"])
        decrypted = _decrypt_hmac(key, encrypted, mac)
        self.attr.update(**_parse_dictionary(decrypted.decode()))

    def disks(self) -> List[str]:
        """Return a list of paths to disk files"""
        dev_classes = ("scsi", "sata", "ide", "nvme")
        devices = {}

        for vm_setting, value in self.attr.items():
            for dev_class in dev_classes:
                if vm_setting.startswith(dev_class):
                    # Properties for disk devices are formatted as
                    # <dev_class><bus_id>:<disk_id>.<dev_property>
                    #
                    # We use <bus_id>:<disk_id> as a unique identifier for
                    # disks to store the properties and their values.
                    # Properties for the bus device are stored with the unique
                    # <bus_id> key.
                    device, dev_property = vm_setting.split(".", 1)
                    dev_id = device.lstrip(dev_class)

                    dev_ids = devices.setdefault(dev_class, {})
                    dev_properties = dev_ids.setdefault(dev_id, {})
                    dev_properties[dev_property] = value
                    break

        disk_files = []
        for dev_properties_by_dev_id in devices.values():
            for dev_properties in dev_properties_by_dev_id.values():
                filename = dev_properties.get("filename")

                if filename:
                    dev_type = dev_properties.get("devicetype")

                    if not dev_type or "disk" in dev_type.lower():
                        disk_files.append(filename)

        return sorted(disk_files)


def _parse_dictionary(string: str) -> Dict[str, str]:
    """Parse a VMX dictionary."""
    dictionary = {}

    for line in string.split("\n"):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, _, value = line.partition("=")
        # Some keys are technically case sensitive, but there are implementations
        # that have different casing for the same key
        dictionary[key.strip().lower()] = value.strip(' "')

    return dictionary


class KeySafe:
    def __init__(self, locators: List[Pair]):
        self.locators = locators

    def unseal_with_phrase(self, passphrase: str) -> bytes:
        """Unseal this KeySafe with a passphrase and return the decrypted key."""
        for locator in self.locators:
            if not locator.has_phrase():
                continue

            try:
                data = locator.unlock_with_phrase(passphrase)
                # Decrypted output is a crypto dict
                # type=key:cipher=AES-256:key=base64value'
                crypto_dict = _parse_crypto_dict(data.decode())
                return base64.b64decode(crypto_dict["key"]), locator.mac
            except ValueError:
                pass

        raise ValueError("No compatible locator")

    @classmethod
    def from_text(cls, text: str) -> KeySafe:
        """Parse a KeySafe from a string."""

        # Key safes are a list of key locators. It's a key locator string with a specific prefix
        identifier, _, remainder = text.partition("/")
        if identifier != "vmware:key":
            raise ValueError("Invalid KeySafe string, wrong identifier")

        # First part must be a list of pairs
        locators = _parse_key_locator(remainder)
        if not isinstance(locators, list) and not all([isinstance(member, Pair) for member in locators]):
            raise ValueError("Invalid KeySafe string, not a list of pairs")

        return KeySafe(locators)


class Pair:
    def __init__(self, wrapped_key, mac: str, data: bytes):
        self.wrapped_key = wrapped_key
        self.mac = mac
        self.data = data

    def __repr__(self):
        return f"<Pair wrapped_key={self.wrapped_key} mac={self.mac}>"

    def has_phrase(self) -> bool:
        """Return whether this Pair is a Phrase pair."""
        return isinstance(self.wrapped_key, Phrase)

    def _unlock(self, key: bytes) -> bytes:
        """Decrypt the data in this Pair."""
        return _decrypt_hmac(key, self.data, self.mac)

    def unlock(self, *args, **kwargs) -> bytes:
        """Helper method to unlock this Pair for various wrapped keys.

        Currently only supports `Phrase`.
        """
        if self.has_phrase():
            return self.unlock_with_phrase(*args, **kwargs)
        else:
            raise TypeError(f"Unable to unlock {self.key}")

    def unlock_with_phrase(self, passphrase: str) -> bytes:
        """Unlock this Pair with a passphrase and return the decrypted data."""
        if not self.has_phrase():
            raise TypeError("Pair doesn't have a phrase protected key")

        key = self.wrapped_key.unwrap(passphrase)
        return self._unlock(key)


class Phrase:
    def __init__(self, id: str, pass2key: str, cipher: str, rounds: int, salt: bytes):
        self.id = id
        self.pass2key = pass2key
        self.cipher = cipher
        self.rounds = rounds
        self.salt = salt

    def __repr__(self):
        return f"<Phrase id={self.id} pass2key={self.pass2key} cipher={self.cipher} rounds={self.rounds}>"

    def unwrap(self, passphrase: str) -> bytes:
        """Unwrap/generate the encryption key for a given passphrase.

        VMware calls this unwrapping, but really it's a KDF with the properties of this Phrase.
        """
        return hashlib.pbkdf2_hmac(
            PASS2KEY_MAP[self.pass2key],
            passphrase.encode(),
            self.salt,
            self.rounds,
            CIPHER_KEY_SIZES[self.cipher],
        )


def _parse_key_locator(locator_string: str):
    """Parse a key locator from a string.

    Key locators are string formatted data structures with a forward slash (/) separator. Each component is
    prefixed with a type, followed by that types' specific data. Values between separators are url encoded.

    Interally called `KeyLocator`.
    """

    identifier, _, remainder = locator_string.partition("/")

    if identifier == "list":
        # Comma separated list in between braces
        # list/(member,member)
        return [_parse_key_locator(member) for member in _split_list(remainder)]
    elif identifier == "pair":
        # Comma separated tuple with 3 members
        # pair/(key data,mac type,encrypted data)
        members = _split_list(remainder)
        return Pair(
            _parse_key_locator(members[0]),
            unquote(members[1]),
            base64.b64decode(unquote(members[2])),
        )
    elif identifier == "phrase":
        # Serialized crypto dict, prefixed with an identifier
        # phrase/encoded id/encoded dict
        phrase_id, _, phrase_data = remainder.partition("/")
        crypto_dict = _parse_crypto_dict(unquote(phrase_data))
        return Phrase(
            unquote(phrase_id),
            crypto_dict["pass2key"],
            crypto_dict["cipher"],
            int(crypto_dict["rounds"]),
            base64.b64decode(crypto_dict["salt"]),
        )
    else:
        # rawkey, ldap, script, role, fqid
        raise NotImplementedError(f"Not implemented keysafe identifier: {identifier}")


def _split_list(list_string: str) -> List[str]:
    """Parse a key locator list from a string.

    Lists are wrapped by braces and separated by comma. They can contain nested lists/pairs,
    so we need to separate at the correct nest level.
    """

    match = re.match(r"\((.+)\)", list_string)
    if not match:
        raise ValueError("Invalid list string")

    contents = match.group(1)

    buf = ""
    members = []
    level = 0
    for char in contents:
        if char == "(":
            level += 1
        elif char == ")":
            level -= 1
        elif char == "," and level == 0:
            members.append(buf)
            buf = ""
            continue

        buf += char

    if buf:
        members.append(buf)

    return members


def _parse_crypto_dict(dict_string: str) -> Dict[str, str]:
    """Parse a crypto dict from a string.

    Crypto dicts are encoded as `key=encoded_value:key=encoded_value`.

    Internally called `CryptoDict`.
    """

    crypto_dict = {}
    for part in dict_string.split(":"):
        key, _, value = part.partition("=")
        crypto_dict[key] = unquote(value)
    return crypto_dict


def _decrypt_hmac(key: bytes, data: bytes, digest: str) -> bytes:
    """Decrypt and validate ciphertext.

    First 16 bytes of the ciphertext are the IV and the last N bytes are the HMAC digest.
    The cleartext is padded using PKCS#7.
    """

    digest, digest_size = HMAC_MAP[digest]

    iv, encrypted, mac = data[:16], data[16:-digest_size], data[-digest_size:]
    cipher = _create_cipher(key, iv)

    decrypted = cipher.decrypt(encrypted)
    if decrypted[-1] <= 16:
        # PKCS#7 padding
        decrypted = decrypted[: -decrypted[-1]]

    # We don't do any secret crypto so we don't care about the warning in the docs about timing attacks
    if hmac.digest(key, decrypted, digest) != mac:
        raise ValueError("Invalid HMAC, wrong key?")

    return decrypted


def _create_cipher(key: bytes, iv: bytes):
    """Create a cipher object.

    Dynamic based on the available crypto module.
    """

    if HAS_PYSTANDALONE:
        if len(key) == 32:
            cipher = "aes-256-cbc"
        elif len(key) == 24:
            cipher = "aes-192-cbc"
        elif len(key) == 16:
            cipher = "aes-128-cbc"
        else:
            raise ValueError(f"Invalid key size: {len(key)}")

        return _pystandalone.cipher(cipher, key, iv)
    elif HAS_PYCRYPTODOME:
        return AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        raise RuntimeError("No crypto module available")
