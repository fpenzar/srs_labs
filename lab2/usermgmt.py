from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from constants import FILE
import sys
import json
from getpass import getpass


def hash(bytes):
    hash_object = SHA256.new(bytes)
    return hash_object.digest()


def create_new_pwd_hash(pwd):
    salt = get_random_bytes(16)
    pwd_bytes = str.encode(pwd)
    salted_pwd_binary = pwd_bytes + salt
    hashed = hash(salted_pwd_binary)
    return hashed, salt


def handle_new_pwd():
    pwd = ""
    while len(pwd) < 8:
        print("[INFO] password must be at least 8 characters long")
        pwd = getpass("Password: ")
    pwd_repeat = getpass("Repeat password: ")

    if pwd != pwd_repeat:
        return False, ""
    
    return True, pwd


def read_passwords():
    with open(FILE, "r") as file:
        file_contents = file.read()
        if not file_contents:
            return {}
        else:
            return json.loads(file_contents)


def write_passwords(passwords):
    with open(FILE, "w") as file:
        file.write(json.dumps(passwords))


def add(user):
    passwords = read_passwords()
    
    if user in passwords:
        print("User already in passwords!")
        return
    
    pwd_ok, pwd = handle_new_pwd()
    if not pwd_ok:
        print("User add fail. Password mismatch.")
        return
    
    hashed, salt = create_new_pwd_hash(pwd)
    passwords.update({user: {"pwd": hashed.hex(), "salt": salt.hex(), "change_pwd": False}})

    write_passwords(passwords)
    
    print(f"User {user} added successfuly.")


def passwd(user):
    passwords = read_passwords()
    
    if user not in passwords:
        print("User not in passwords!")
        return
    
    print("NEW PASSWORD:")
    pwd_ok, pwd = handle_new_pwd()
    if not pwd_ok:
        print("Password change fail. Password mismatch.")
        return
    
    hashed, salt = create_new_pwd_hash(pwd)
    passwords[user]["pwd"] = hashed.hex()
    passwords[user]["salt"] = salt.hex()

    write_passwords(passwords)
    
    print(f"User {user} password change successful.")


def forcepass(user):
    passwords = read_passwords()
    
    if user not in passwords:
        print("User not in passwords!")
        return
    
    passwords[user]["change_pwd"] = True
    write_passwords(passwords)
    
    print(f"User {user} will be requested to change password on next login.")


def delete(user):
    passwords = read_passwords()
    
    if user not in passwords:
        print("User not in passwords!")
        return

    del passwords[user]
    write_passwords(passwords)
    
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
