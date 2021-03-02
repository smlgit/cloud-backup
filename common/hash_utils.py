import hashlib


empty_file_md5_hex_str = 'd41d8cd98f00b204e9800998ecf8427e'


def _calc_file_hash(hasher_name, file_path, return_hex):
    hasher = hashlib.new(hasher_name)
    with open(file_path, 'rb') as f:
        while True:
            bytes = f.read(1024)
            if len(bytes) > 0:
                hasher.update(bytes)
            else:
                break

    if return_hex is True:
        return hasher.hexdigest()

    return hasher.digest()


def _calc_bytes_hash(hasher_name, bytes_or_string, return_hex):
    hasher = hashlib.new(hasher_name)
    hasher.update(bytes_or_string)

    if return_hex is True:
        return hasher.hexdigest()

    return hasher.digest()


def calc_file_md5_hex_str(file_path):
    return _calc_file_hash('md5', file_path, True)


def calc_file_sha1_hex_str(file_path):
    return _calc_file_hash('sha1', file_path, True)


def calc_str_md5_hex_str(s):
    return _calc_bytes_hash('md5', s, True)


def calc_str_sha1_bytes(s):
    return _calc_bytes_hash('sha1', s, False)


def calc_file_sha1_bytes(file_path):
    return _calc_file_hash('sha1', file_path, False)