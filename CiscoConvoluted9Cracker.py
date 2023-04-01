import hashlib
import scrypt
import base64
from passlib.hash import md5_crypt
import argparse
import multiprocessing
import functools
import time
 
# Translate Standard Base64 table to Cisco Base64 Table used in Type8 and TYpe 9                                            	
std_b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cisco_b64chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
b64table = str.maketrans(std_b64chars, cisco_b64chars)
 
def pwd_check(pwd):
    invalid_chars = r"?\""
    if len(pwd) > 127 or any(char in invalid_chars for char in pwd):
        return False
    return True
 
def type5(pwd, salt):
    return md5_crypt.using(salt_size=4, salt=salt).hash(pwd)
 
def type9(pwd, salt):
    # Create the hash
    pwd_hash = scrypt.hash(pwd.encode(), salt.encode(), 16384, 1, 1, 32)
    # Convert the hash from Standard Base64 to Cisco Base64
    pwd_hash = base64.b64encode(pwd_hash).decode().translate(b64table)[:-1]
    # Print the hash in the Cisco IOS CLI format
    password_string = f'{pwd_hash}'
    return password_string
 
def type14(word, type5_salt, type9_salt):
    word = word.rstrip()
    if pwd_check(word):
        return type9(type5(word, type5_salt), type9_salt), word
    return False
     
def parse_convoluted_password(pwd):
    _, _, type5_salt, type9_salt, hashed_pwd = pwd.split("$")
    return type5_salt, type9_salt, hashed_pwd
 
 
def main():
    parser = argparse.ArgumentParser(description="Tries to Crack Cisco Convoluted 9 Passwords")
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-w", "--wordlist", required=True)
    parser.add_argument("-t", "--threads", type=int, default=1)
    args = parser.parse_args()
    pool = multiprocessing.Pool(args.threads)


    type5_salt, type9_salt, hashed_pwd = parse_convoluted_password(args.password)
    hashed_wordlist = []
 
    partial_process_line = functools.partial(type14, type5_salt=type5_salt,
                                             type9_salt=type9_salt)
     
    with open(args.wordlist) as words:
        results = pool.map(partial_process_line, words)
        for result in results:
            if result[0] == hashed_pwd:
                print(result[1])
                pool.terminate()
                break
     
if __name__ == "__main__":
    start_time = time.time()
    main()
    print("--- %.2f seconds ---" % (time.time() - start_time))
