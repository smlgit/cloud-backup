import hashlib


empty_file_md5_hex_str = 'd41d8cd98f00b204e9800998ecf8427e'


def _calc_hash_hex_str(hasher_name, file_path):
    hasher = hashlib.new(hasher_name)
    with open(file_path, 'rb') as f:
        while True:
            bytes = f.read(1024)
            if len(bytes) > 0:
                hasher.update(bytes)
            else:
                break

    return hasher.hexdigest()


def calc_md5_hex_str(file_path):
    return _calc_hash_hex_str('md5', file_path)


def calc_sha1_hex_str(file_path):
    return _calc_hash_hex_str('sha1', file_path)