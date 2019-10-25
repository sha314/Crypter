from builtins import bytes
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def encrypt(string, password):
    """
    It returns an encrypted string which can be decrypted just by the
    password.
    """
    key = password_to_key(password)
    IV = make_initialization_vector()
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    # store the IV at the beginning and encrypt
    return IV + encryptor.encrypt(pad_string(string))

def decrypt(string, password):
    key = password_to_key(password)

    # extract the IV from the beginning
    IV = string[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)

    string = decryptor.decrypt(string[AES.block_size:])
    return unpad_string(string)

def password_to_key(password):
    """
    Use SHA-256 over our password to get a proper-sized AES key.
    This hashes our password into a 256 bit string.
    """
    return SHA256.new(password).digest()

def make_initialization_vector():
    """
    An initialization vector (IV) is a fixed-size input to a cryptographic
    primitive that is typically required to be random or pseudorandom.
    Randomization is crucial for encryption schemes to achieve semantic
    security, a property whereby repeated usage of the scheme under the
    same key does not allow an attacker to infer relationships
    between segments of the encrypted message.
    """
    return Random.new().read(AES.block_size)

def pad_string(string, chunk_size=AES.block_size):
    """
    Pad string the peculirarity that uses the first byte
    is used to store how much padding is applied
    """
    assert chunk_size  <= 256, 'We are using one byte to represent padding'
    to_pad = (chunk_size - (len(string) + 1)) % chunk_size
    return bytes([to_pad]) + string + bytes([0] * to_pad)
def unpad_string(string):
    to_pad = string[0]
    return string[1:-to_pad]

def encode(string):
    """
    Base64 encoding schemes are commonly used when there is a need to encode
    binary data that needs be stored and transferred over media that are
    designed to deal with textual data.
    This is to ensure that the data remains intact without
    modification during transport.
    """
    return base64.b64encode(string).decode("latin-1")

def decode(string):
    return base64.b64decode(string.encode("latin-1"))






def random_text(length):
    def rand_lower():
        return chr(randint(ord('a'), ord('z')))
    string = ''.join([rand_lower() for _ in range(length)])
    return bytes(string, encoding='utf-8')

def test_encoding():
    string = random_text(100)
    assert encode(string) != string
    assert decode(encode(string)) == string

def test_padding():
    assert len(pad_string(random_text(14))) == 16
    assert len(pad_string(random_text(15))) == 16
    assert len(pad_string(random_text(16))) == 32

def test_encryption():
    string = random_text(100)
    password = random_text(20)
    assert encrypt(string, password) != string
    assert decrypt(encrypt(string, password), password) == string


