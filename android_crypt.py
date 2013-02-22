#!/usr/bin/env python

from collections import namedtuple
import getpass
import os
import struct
import subprocess
import sys

import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import Crypto.Hash.SHA
from pbkdf2 import PBKDF2


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


def get_crypt_ftr_and_key(disk_image):
    with open(disk_image, 'rb') as fh:
        fh.seek(-CRYPT_FOOTER_OFFSET, os.SEEK_END)
        footer = fh.read(CryptMntFtr.struct_size())
        if len(footer) < CryptMntFtr.struct_size():
            print("Cannot read disk image footer")
            return None
        crypt_ftr = CryptMntFtr(footer)

        if crypt_ftr.magic != CRYPT_MNT_MAGIC:
            print("Bad magic in disk image footer")
            return None
        if crypt_ftr.major_version != 1:
            print("Cannot understand major version {} "
                  "in disk image footer".format(crypt_ftr.major_version))
            return None
        if crypt_ftr.minor_version != 0:
            print("Warning: crypto footer minor version {}, "
                  "expected 0, continuing...".format(crypt_ftr.minor_version))

        if crypt_ftr.ftr_size > CryptMntFtr.struct_size():
            # skip to the end of the footer so we can read the key
            fh.seek(crypt_ftr.ftr_size - CryptMntFtr.struct_size(), os.SEEK_CUR)

        if crypt_ftr.keysize != KEY_LEN_BYTES:
            print("Keysize of {} bits not supported".format(
                    crypt_ftr.keysize*8))
            return None
        key = fh.read(crypt_ftr.keysize)
        if len(key) != crypt_ftr.keysize:
            print("Cannot read key from disk image footer")
            return None

        fh.seek(KEY_TO_SALT_PADDING, os.SEEK_CUR)
        salt = fh.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            print("Cannot read salt from disk image footer")
            return None

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

def cryptsetup_mount(disk_image, mnt_dir, key, crypt_ftr, label="userdata"):
    cmd = ["sudo", "cryptsetup",
           "-h", "plain",
           "-c", crypt_ftr.crypto_type_name,
           "-d-", "-s", str(KEY_LEN_BYTES*8),
           "create", label, disk_image,
           ]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    p.communicate(key)
    if p.returncode != 0:
        print("cryptsetup returned error code: {}".format(p.returncode))
        return False
    cmd = ["sudo", "mount", "/dev/mapper/{}".format(label), mnt_dir]
    rc = subprocess.call(cmd)
    if rc != 0:
        print("mount returned an error code: {}".format(rc))
        return False
    return True

def mount_android_image(disk_image, mnt_dir, label="userdata"):
    (crypt_ftr, encrypted_key, salt) = get_crypt_ftr_and_key(disk_image)
    if crypt_ftr.flags & CRYPT_MNT_KEY_UNENCRYPTED:
        decrypted_key = encrypted_key
    else:
        password = getpass.getpass()
        decrypted_key = decrypt_key(encrypted_key, salt, password)

    return cryptsetup_mount(disk_image, mnt_dir,
                            decrypted_key, crypt_ftr,
                            label=label)

def cryptsetup_umount(label, mnt_dir):
    cmd = ["sudo", "umount", mnt_dir]
    rc = subprocess.call(cmd)
    if rc != 0:
        print("umount returned an error code: {}".format(rc))
        return False
    cmd = ["sudo", "cryptsetup", "remove", label]
    rc = subprocess.call(cmd)
    if rc != 0:
        print("cryptsetup returned an error code: {}".format(rc))
        return False
    return True

def main(args):
    cmd = args.pop(0)
    if cmd == 'mount':
        disk_image, mnt_dir = args
        mount_android_image(disk_image, mnt_dir)
    elif cmd == 'umount':
        (mnt_dir,) = args
        cryptsetup_umount("userdata", mnt_dir)
    elif cmd == 'changepw':
        (disk_image,) = args
        changepw_android_image(disk_image)

if __name__ == '__main__':
    main(sys.argv[1:])

