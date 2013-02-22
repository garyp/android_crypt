#!/usr/bin/env python

from collections import namedtuple
import getpass
import os
import struct
import subprocess
import sys
from warnings import warn

import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import Crypto.Hash.SHA
from pbkdf2 import PBKDF2


DEFAULT_DATA_LABEL = "userdata"


## from system/vold/cryptfs.h
# /* This structure starts 16,384 bytes before the end of a hardware
#  * partition that is encrypted.
#  * Immediately following this structure is the encrypted key.
#  * The keysize field tells how long the key is, in bytes.
#  * Then there is 32 bytes of padding,
#  * Finally there is the salt used with the user password.
#  * The salt is fixed at 16 bytes long.
#  * Obviously, the filesystem does not include the last 16 kbytes
#  * of the partition.
#  */

CRYPT_FOOTER_OFFSET = 0x4000

MAX_CRYPTO_TYPE_NAME_LEN = 64

SALT_LEN = 16
KEY_TO_SALT_PADDING = 32

# /* definitions of flags in the structure below */
CRYPT_MNT_KEY_UNENCRYPTED = 0x1 # /* The key for the partition is not encrypted. */
CRYPT_ENCRYPTION_IN_PROGRESS = 0x2 # /* Set when starting encryption,
                                   #  * clear when done before rebooting */

CRYPT_MNT_MAGIC = 0xD0B5B1C4

# #define __le32 unsigned int
# #define __le16 unsigned short int
#
# struct crypt_mnt_ftr {
#   __le32 magic;         /* See above */
#   __le16 major_version;
#   __le16 minor_version;
#   __le32 ftr_size;      /* in bytes, not including key following */
#   __le32 flags;         /* See above */
#   __le32 keysize;       /* in bytes */
#   __le32 spare1;        /* ignored */
#   __le64 fs_size;       /* Size of the encrypted fs, in 512 byte sectors */
#   __le32 failed_decrypt_count; /* count of # of failed attempts to decrypt and
#                                   mount, set to 0 on successful mount */
#   unsigned char crypto_type_name[MAX_CRYPTO_TYPE_NAME_LEN]; /* The type of encryption
#                                                                needed to decrypt this
#                                                                partition, null terminated */
# };
## end system/vold/cryptfs.h

## from system/vold/cryptfs.c
HASH_COUNT = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES = 16
## end system/vold/cryptfs.c


class CryptMntFtr(namedtuple('CryptMntFtr', (
        'magic',
        'major_version',
        'minor_version',
        'ftr_size',
        'flags',
        'keysize',
        'fs_size',
        'failed_decrypt_count',
        'crypto_type_name',
        ))):

    __slots__ = ()

    _struct = struct.Struct(
            '<I HH I I I 4x Q I {}s'.format(MAX_CRYPTO_TYPE_NAME_LEN))

    def __new__(cls, bytestring):
        footer_tuple = cls._struct.unpack(bytestring)
        named_footer = super(CryptMntFtr, cls).__new__(cls, *footer_tuple)
        return named_footer._replace(
                crypto_type_name=named_footer.crypto_type_name.rstrip("\0"))

    @classmethod
    def struct_size(cls):
        return cls._struct.size


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class BadCryptFtrError(ValueError, Error):
    """Exception raised for malformed or illegal CryptMntFtr values."""

    def __init__(self, filename, footer, msg):
        super(BadCryptFtrError, self).__init__(filename, footer, msg)
        self.filename = filename
        self.footer = footer
        self.msg = msg


class CalledProcessError(subprocess.CalledProcessError, Error):
    """Exception raised when a subprocess returns a non-zero exit code."""
    pass


def get_crypt_ftr_and_key(disk_image):
    with open(disk_image, 'rb') as fh:
        fh.seek(-CRYPT_FOOTER_OFFSET, os.SEEK_END)
        footer = fh.read(CryptMntFtr.struct_size())
        if len(footer) < CryptMntFtr.struct_size():
            raise BadCryptFtrError(disk_image, None,
                                   "Cannot read disk image footer")
        crypt_ftr = CryptMntFtr(footer)

        if crypt_ftr.magic != CRYPT_MNT_MAGIC:
            raise BadCryptFtrError(
                    disk_image, crypt_ftr, "Bad magic in disk image footer")
        if crypt_ftr.major_version != 1:
            raise BadCryptFtrError(disk_image, crypt_ftr,
                                   "Cannot understand major version {} in "
                                   "disk image footer".format(
                                       crypt_ftr.major_version))
        if crypt_ftr.minor_version != 0:
            warn("crypto footer minor version {}, expected 0".format(
                crypt_ftr.minor_version), UserWarning)

        if crypt_ftr.ftr_size > CryptMntFtr.struct_size():
            # skip to the end of the footer so we can read the key
            fh.seek(crypt_ftr.ftr_size - CryptMntFtr.struct_size(), os.SEEK_CUR)

        if crypt_ftr.keysize != KEY_LEN_BYTES:
            raise BadCryptFtrError(disk_image, crypt_ftr,
                                   "Keysize of {} bits not supported".format(
                                       crypt_ftr.keysize*8))
        key = fh.read(crypt_ftr.keysize)
        if len(key) != crypt_ftr.keysize:
            raise BadCryptFtrError(disk_image, crypt_ftr,
                                   "Cannot read key from disk image footer")

        fh.seek(KEY_TO_SALT_PADDING, os.SEEK_CUR)
        salt = fh.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            raise BadCryptFtrError(disk_image, crypt_ftr,
                                   "Cannot read salt from disk image footer")

    return (crypt_ftr, key, salt)

def decrypt_key(encrypted_key, salt, password):
    pbkdf_f = PBKDF2(password, salt,
                     iterations=HASH_COUNT,
                     macmodule=Crypto.Hash.HMAC,
                     digestmodule=Crypto.Hash.SHA)
    key = pbkdf_f.read(KEY_LEN_BYTES)
    iv = pbkdf_f.read(IV_LEN_BYTES)

    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    decrypted_key = cipher.decrypt(encrypted_key)
    return decrypted_key

def get_decrypted_key(crypt_ftr, encrypted_key, salt, prompt=None):
    if crypt_ftr.flags & CRYPT_MNT_KEY_UNENCRYPTED:
        decrypted_key = encrypted_key
    else:
        if prompt:
            password = getpass.getpass(prompt)
        else:
            password = getpass.getpass()
        decrypted_key = decrypt_key(encrypted_key, salt, password)
    return decrypted_key

def cryptsetup_create(disk_image, key, crypt_ftr, label=DEFAULT_DATA_LABEL):
    cmd = ["sudo", "cryptsetup",
           "-h", "plain",
           "-c", crypt_ftr.crypto_type_name,
           "-d-", "-s", str(KEY_LEN_BYTES*8),
           "create", label, disk_image,
           ]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    p.communicate(key)
    if p.returncode != 0:
        raise CalledProcessError(returncode=p.returncode,
                                 cmd=' '.join(cmd))

def mount_dm_dev(mnt_dir, dm_dev=DEFAULT_DATA_LABEL):
    cmd = ["sudo", "mount", "/dev/mapper/{}".format(dm_dev), mnt_dir]
    rc = subprocess.call(cmd)
    if rc != 0:
        raise CalledProcessError(returncode=rc, cmd=' '.join(cmd))

def decrypt_android_image(disk_image, label=DEFAULT_DATA_LABEL):
    (crypt_ftr, encrypted_key, salt) = get_crypt_ftr_and_key(disk_image)
    decrypted_key = get_decrypted_key(crypt_ftr, encrypted_key, salt)
    cryptsetup_create(disk_image, decrypted_key, crypt_ftr, label=label)

def umount_dm_dev(mnt_dir):
    cmd = ["sudo", "umount", mnt_dir]
    rc = subprocess.call(cmd)
    if rc != 0:
        raise CalledProcessError(returncode=rc, cmd=' '.join(cmd))

def cryptsetup_remove(label=DEFAULT_DATA_LABEL):
    cmd = ["sudo", "cryptsetup", "remove", label]
    rc = subprocess.call(cmd)
    if rc != 0:
        raise CalledProcessError(returncode=rc, cmd=' '.join(cmd))

def main(args):
    cmd = args.pop(0)
    if cmd == 'decrypt':
        (disk_image,) = args
        decrypt_android_image(disk_image)
    elif cmd == 'mount':
        disk_image, mnt_dir = args
        decrypt_android_image(disk_image)
        mount_dm_dev(mnt_dir)
    elif cmd == 'umount':
        (mnt_dir,) = args
        umount_dm_dev(mnt_dir)
        cryptsetup_remove()
    elif cmd == 'decrypt_cleanup':
        cryptsetup_remove()
    elif cmd == 'changepw':
        (disk_image,) = args
        changepw_android_image(disk_image)

if __name__ == '__main__':
    main(sys.argv[1:])

