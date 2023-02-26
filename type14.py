import hashlib
import scrypt
import base64
from passlib.hash import md5_crypt

# Translate Standard Base64 table to Cisco Base64 Table used in Type8 and TYpe 9                                                
std_b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cisco_b64chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
b64table = str.maketrans(std_b64chars, cisco_b64chars)

def pwd_check(pwd):
    """
    Checks cleartext password for invalid characters
    :param pwd: Clear text password
    :raises InvalidPassword: If the password contains invalid characters not supported by Cisco
    :return: None
    """
    invalid_chars = r"?\""
    if len(pwd) > 127:
        raise InvalidPassword('Password must be between 1 and 127 characters in length.')
    if any(char in invalid_chars for char in pwd):
        raise InvalidPassword(r'? and \" are invalid characters for Cisco passwords.')

def type5(pwd, salt):
    """
    Hashes cleartext password to Cisco type 5
    :param pwd: Clear text password to be hashed
    :raises InvalidPassword: If the password contains invalid characters not supported by Cisco
    :return: Hashed password
    """
    pwd_check(pwd)
    return md5_crypt.using(salt_size=4, salt=salt).hash(pwd)

def type9(pwd, salt):
    """
    Hashes password to Cisco type 9
    :param pwd: Clear text password
    :raises InvalidPassword: If the password contains invalid characters not supported by Cisco
    :return: Hashed password
    """
    pwd_check(pwd)
    # Create the hash
    pwd_hash = scrypt.hash(pwd.encode(), salt.encode(), 16384, 1, 1, 32)
    # Convert the hash from Standard Base64 to Cisco Base64
    pwd_hash = base64.b64encode(pwd_hash).decode().translate(b64table)[:-1]
    # Print the hash in the Cisco IOS CLI format
    password_string = f'{pwd_hash}'
    return password_string

def main():
    enc = "C9D/fD0czicOtgaZAa1CTa2sgygi0Leyw3/cLqPY426"
    type5_salt = "dNmW"
    type9_salt = "QykGZEEGmiEGrE"
    wordlist =  ["1234", "qwer", "abcd"]

    md5_wordlist = []
    scrypt_wordlist = []
    
    #encrypt wordlist
    for word in wordlist:
        #hashed_word = hashlib.md5(type5_salt.encode('utf-8') + word.encode('utf-8')).hexdigest()
        hashed_word = type5(word, type5_salt)
        md5_wordlist.append(hashed_word)

    for word in md5_wordlist:
        hashed_word = type9(word, type9_salt)
        scrypt_wordlist.append(hashed_word)

    #Dictionary Attack
    for word in scrypt_wordlist:
        if word == enc:
            print(wordlist[scrypt_wordlist.index(word)])

if __name__ == "__main__":
    main()


