from constants import FILE
import sys
from getpass import getpass
from usermgmt import hash, read_passwords, write_passwords, handle_new_pwd, create_new_pwd_hash


def login(user):
    passwords = read_passwords()
    
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
    print("NEW PASSWORD REQUIRED!")
    pwd_ok, pwd = handle_new_pwd()
    if not pwd_ok:
        print("Password change fail. Password mismatch.")
        return
    
    hashed, salt = create_new_pwd_hash(pwd)
    passwords[user]["pwd"] = hashed.hex()
    passwords[user]["salt"] = salt.hex()
    passwords[user]["change_pwd"] = False

    write_passwords(passwords)
    
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