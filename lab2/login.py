from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from constants import FILE
import sys
import json
from getpass import getpass
from usermgmt import hash


def login(user):
    with open(FILE, "r") as file:
        file_contents = file.read()
        if not file_contents:
            passwords = {}
        else:
            passwords = json.loads(file_contents)
    
    
    pwd_valid = False
    while not pwd_valid:
        pwd = getpass("Password: ")
        if user not in passwords:
            print("Username or password incorrect.")
            continue
        
        pwd_bytes_db = bytes.fromhex(passwords[user]["pwd"])

        salt = bytes.fromhex(passwords[user]["salt"])
        pwd_bytes = str.encode(pwd)
        salted_pwd_binary = pwd_bytes + salt
        hashed = hash(salted_pwd_binary)
        if hashed == pwd_bytes_db:
            pwd_valid = True
        else:
            print("Username or password incorrect.")
    
    if not passwords[user]["change_pwd"]:
        print("Login successful!")
        return
    
    # change password part
    pwd = ""
    while len(pwd) < 8:
        print("[INFO] New password must be at least 8 characters long")
        pwd = getpass("New password: ")
    pwd_repeat = getpass("Repeat new password: ")

    if pwd != pwd_repeat:
        print("Password change fail. Password mismatch.")
        return
    
    salt = get_random_bytes(16)
    pwd_bytes = str.encode(pwd)
    salted_pwd_binary = pwd_bytes + salt
    hashed = hash(salted_pwd_binary)
    passwords[user]["pwd"] = hashed.hex()
    passwords[user]["salt"] = salt.hex()
    passwords[user]["change_pwd"] = False

    with open(FILE, "w") as file:
        file.write(json.dumps(passwords))
    
    print("Login successful!")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Wrong usage: Expected 1 arg, got {len(sys.argv) - 1} instead")
        exit(1)
    
    user = sys.argv[1]

    # create file if missing
    with open(FILE, "a") as file:
        pass

    login(user)