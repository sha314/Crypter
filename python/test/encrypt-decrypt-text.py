import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("utf-8") if encode else data


def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("utf-8"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


my_password = b"secret_AES_key_string_to_encrypt/decrypt_with"
my_password = b"k"
my_data = b"input_string_to_encrypt/decrypt"

print("key:  {}".format(my_password))
print("data: {}".format(my_data))
encrypted = encrypt(my_password, my_data)
print("\nenc:  {}".format(encrypted))
decrypted = decrypt(my_password, encrypted)
print("dec:  {}".format(decrypted))
print("\ndata match: {}".format(my_data == decrypted))


print("\nSecond round....")
encrypted = encrypt(my_password, my_data)
print("\nenc:  {}".format(encrypted))
decrypted = decrypt(my_password, encrypted)
print("dec:  {}".format(decrypted))
print("\ndata match: {}".format(my_data == decrypted))
