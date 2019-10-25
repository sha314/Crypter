import hashlib
import os

# Generating a Salt
salt = os.urandom(32) # Remember this
print(len(salt))
"""
 os.urandom(size)

    Return a string of size random bytes suitable for cryptographic use.

    This function returns random bytes from an OS-specific randomness source. The returned data should be unpredictable enough for cryptographic applications, though its exact quality depends on the OS implementation.

    On Linux, if the getrandom() syscall is available, it is used in blocking mode: block until the system urandom entropy pool is initialized (128 bits of entropy are collected by the kernel). See the PEP 524 for the rationale. On Linux, the getrandom() function can be used to get random bytes in non-blocking mode (using the GRND_NONBLOCK flag) or to poll until the system urandom entropy pool is initialized.

    On a Unix-like system, random bytes are read from the /dev/urandom device. If the /dev/urandom device is not available or not readable, the NotImplementedError exception is raised.

    On Windows, it will use CryptGenRandom().
"""
print("salt ", salt)
password = 'password123'


# Hashing
def get_key(password, salt, dklength=32):
    print('Hashing')
    key = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000,  # It is recommended to use at least 100,000 iterations of SHA-256
        dklen=dklength  # Get a 128 byte key
    )
    return key


# Storing
def store(password, salt, dklength=32):
    print("Storing")
    print(len(salt))
    # Example generation
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=dklength)

    # Store them as:
    storage = salt + key
    print(storage)
    # Getting the values back out
    salt_from_storage = storage[:len(salt)] # len(salt) is the length of the salt
    key_from_storage = storage[len(salt):]
    print("salt ")
    print(salt_from_storage)
    print("key ")
    print(key_from_storage)
    return storage


def verify(password_to_check, salt,  key, dklength=32):
    # Verify
    # salt = b'' # Get the salt you stored for *this* user
    # key = b'' # Get this users key calculated

    # Use the exact same setup you used to generate the key, but this time put in the password to check
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        password_to_check.encode('utf-8'), # Convert the password to bytes
        salt,
        100000,
        dklen=dklength
    )

    if new_key == key:
        print('Password is correct')
    else:
        print('Password is incorrect')
        pass
    pass


key = get_key('password123', salt)

verify('password123', salt, key)
verify('password023', salt, key)



def encrypt(data, password, salt, ):
    a = hashlib.scrypt(password, data, salt, n, r, p, maxmem=0, dklen=64)
    print(a)