from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from constants import FILE
import sys
import json
from getpass import getpass


def hash(bytes):
    hash_object = SHA256.new(bytes)
    return hash_object.digest()


def add(user):
    with open(FILE, "r") as file:
        file_contents = file.read()
        if not file_contents:
            passwords = {}
        else:
            passwords = json.loads(file_contents)
    
    if user in passwords:
        print("User already in passwords!")
        return
    
    pwd = ""
    while len(pwd) < 8:
        print("[INFO] password must be at least 8 characters long")
        pwd = getpass("Password: ")
    pwd_repeat = getpass("Repeat password: ")

    if pwd != pwd_repeat:
        print("User add fail. Password mismatch.")
        return
    
    salt = get_random_bytes(16)
    pwd_bytes = str.encode(pwd)
    salted_pwd_binary = pwd_bytes + salt
    hashed = hash(salted_pwd_binary)
    passwords.update({user: {"pwd": hashed.hex(), "salt": salt.hex(), "change_pwd": False}})

    with open(FILE, "w") as file:
        file.write(json.dumps(passwords))
    
    print(f"User {user} added successfuly.")


def passwd(user):
    with open(FILE, "r") as file:
        file_contents = file.read()
        if not file_contents:
            passwords = {}
        else:
            passwords = json.loads(file_contents)
    
    if user not in passwords:
        print("User not in passwords!")
        return
    
    pwd = ""
    while len(pwd) < 8:
        print("[INFO] password must be at least 8 characters long")
        pwd = getpass("Password: ")
    pwd_repeat = getpass("Repeat password: ")

    if pwd != pwd_repeat:
        print("Password change fail. Password mismatch.")
        return
    
    salt = get_random_bytes(16)
    pwd_bytes = str.encode(pwd)
    salted_pwd_binary = pwd_bytes + salt
    hashed = hash(salted_pwd_binary)
    passwords[user]["pwd"] = hashed.hex()
    passwords[user]["salt"] = salt.hex()

    with open(FILE, "w") as file:
        file.write(json.dumps(passwords))
    
    print(f"User {user} password change successful.")


def forcepass(user):
    with open(FILE, "r") as file:
        file_contents = file.read()
        if not file_contents:
            passwords = {}
        else:
            passwords = json.loads(file_contents)
    
    if user not in passwords:
        print("User not in passwords!")
        return
    
    passwords[user]["change_pwd"] = True
    with open(FILE, "w") as file:
        file.write(json.dumps(passwords))
    
    print(f"User {user} will be requested to change password on next login.")


def delete(user):
    with open(FILE, "r") as file:
        file_contents = file.read()
        if not file_contents:
            passwords = {}
        else:
            passwords = json.loads(file_contents)
    
    if user not in passwords:
        print("User not in passwords!")
        return

    del passwords[user]
    with open(FILE, "w") as file:
        file.write(json.dumps(passwords))
    
    print(f"User {user} has been deleted.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Wrong usage: Expected 2 args, got {len(sys.argv) - 1} instead")
        exit(1)
    
    command = sys.argv[1]
    user = sys.argv[2]

    # create file if missing
    with open(FILE, "a") as file:
        pass

    if command == "add":
        add(user)
    elif command == "passwd":
        passwd(user)
    elif command == "forcepass":
        forcepass(user)
    elif command == "del":
        delete(user)
    else:
        print("[ERROR] command not recognized!")
        exit(1)
