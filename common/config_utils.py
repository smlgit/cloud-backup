import pickle
import base64
import os
import shutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


"""
Provides basic functions to save config objects to an encrypted file
using a password to generate the key.
"""

def _get_salt_file_path(config_file_path):
    return config_file_path + '.salty-xxcffv.txt'


def _get_fernet(salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)


def save_config(config_object, config_file_path, password):
    # First check to see if this config file has an existing
    # salt file. If not, generate a salt and file.

    password = bytearray(password, encoding='utf-8')

    if os.path.exists(_get_salt_file_path(config_file_path)) is False:
        with open(_get_salt_file_path(config_file_path), 'wb') as f:
            f.write(os.urandom(16))

    with open(_get_salt_file_path(config_file_path), 'rb') as f:
        salt = f.readline()

    fern = _get_fernet(salt, password)
    token = fern.encrypt(pickle.dumps(config_object))

    with open(config_file_path, 'wb') as f:
        f.write(token)


def get_config(config_file_path, password):

    password = bytearray(password, encoding='utf-8')

    with open(_get_salt_file_path(config_file_path), 'rb') as f:
        salt = f.readline()

    with open(config_file_path, 'rb') as f:
        token = f.read()

    fern = _get_fernet(salt, password)
    return pickle.loads(fern.decrypt(token))


def change_config_password(config_file_path, old_password, new_password):
    # Load existing config
    config_object = get_config(config_file_path, old_password)

    # Remove salt file, save backup in case something goes wrong.
    shutil.copy(config_file_path, config_file_path + '.bu')
    shutil.copy(_get_salt_file_path(config_file_path),
                _get_salt_file_path(config_file_path) +'.bu')
    os.remove(_get_salt_file_path(config_file_path))

    # Save config with new password (will automatically save new salt file
    save_config(config_object, config_file_path, new_password)

    os.remove(config_file_path + '.bu')
    os.remove(_get_salt_file_path(config_file_path) + '.bu')