from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import sys
import json


class PasswordManager:

    def __init__(self):
        self.commands = {
            "put": self.put,
            "get": self.get,
            "init": self.init
        }
        self.filename = "passwords"

        if len(sys.argv) < 3:
            print("Invalid args!")
            exit()
        
        # validate user command
        self.command = sys.argv[2]
        if self.command not in self.commands.keys():
            print("Invalid command")
            exit()
        
        # get the two keys
        # generate salt
        self.salt = self.get_salt()
        self.b_user_password = str.encode(sys.argv[1]) # get the bytes from the pwd
        keys = PBKDF2(self.b_user_password, salt=self.salt, dkLen=64, count=1000000, hmac_hash_module=SHA512)
        self.confidentiality_key = keys[:32] #256 bit key
        self.integrity_key = keys[32:] #256 bit key
        
        self.placeholder_value = {}
        
        # execute command
        args = sys.argv[3:]
        self.commands[self.command](*args)
    

    def get_salt(self):
        """
        if PasswordManager has already been initialized, read the salt from the saved file
        otherwise generate random salt 16 bytes long
        """
        if self.command == "init":
            return get_random_bytes(16)
        with open(self.filename, "r") as file:
            return bytes.fromhex(json.loads(file.read())["salt"])


    def init(self, *args):
        # init a new pwd_file
        with open(self.filename, "w") as file:
            encoded_placeholder = self.encode_passwords(self.placeholder_value)
            file.write(json.dumps({
                "contents": encoded_placeholder.hex(), # save the encrypted contents as string
                "mac": self.get_mac(encoded_placeholder), # get message authentication code for the contents
                "salt": self.salt.hex() # save the newly generated salt (has to be a string)
            }))
        print("Password manager initialized")
    

    def read_file(self):
        with open(self.filename, "r") as file:
            file_contents_raw = file.read()
        try:
            file_contents = json.loads(file_contents_raw)
            file_contents["contents"]
            file_contents["mac"]
        except:
            print("File corrupted!")
            exit()
        return file_contents
    

    def integrity_check(self, file_contents):
        b_contents = bytes.fromhex(file_contents["contents"])
        h = HMAC.new(self.integrity_key, digestmod=SHA256)
        h.update(b_contents)
        try:
            h.hexverify(file_contents["mac"])
            return True
        except ValueError:
            return False
    

    def decode_passwords(self, contents):
        b_contents = bytes.fromhex(contents)
        msg_nonce = b_contents[:8]
        ciphertext = b_contents[8:]
        cipher = Salsa20.new(key=self.confidentiality_key, nonce=msg_nonce)
        return cipher.decrypt(ciphertext)
    

    def encode_passwords(self, contents):
        """
        encode the contents using a stream cypher
        """
        cipher = Salsa20.new(self.confidentiality_key)
        return cipher.nonce + cipher.encrypt(str.encode(json.dumps(contents)))
    

    def get_mac(self, contents):
        """
        generate Message Authentication Code
        """
        h = HMAC.new(self.integrity_key, digestmod=SHA256)
        h.update(contents)
        return h.hexdigest()


    def put(self, *args):
        """
        Store a new address: password
        """
        if (len(args) != 2):
            print("Invalid syntax")
            exit()
        
        address = args[0]
        password = args[1]
        # read file contents
        file_contents = self.read_file()
        # check integrity
        if not self.integrity_check(file_contents):
            print("Master password incorrect or integrity check failed.")
            exit()
        
        passwords = json.loads(self.decode_passwords(file_contents["contents"]))
        # save the new password to the right address
        passwords[address] = password 
        # encode the whole json
        encoded_pwds = self.encode_passwords(passwords) 
        file_contents["contents"] = encoded_pwds.hex() 
        file_contents["mac"] = self.get_mac(encoded_pwds)

        # save to file
        with open(self.filename, "w") as file:
            file.write(json.dumps(file_contents))

        print(f"Stored password for {address}")


    def get(self, *args):
        """
        Get the password for the specified address
        """
        if (len(args) != 1):
            print("Invalid syntax")
            exit()

        address = args[0]
        # read file contents
        file_contents = self.read_file()
        # check integrity
        if not self.integrity_check(file_contents):
            print("Master password incorrect or integrity check failed.")
            exit()
        
        passwords = json.loads(self.decode_passwords(file_contents["contents"]))
        if address not in passwords.keys():
            print("Specified address not saved!")
            exit()
        
        print(f"Password for {address} is: {passwords[address]}")


if __name__ == '__main__':
    pwd_manager = PasswordManager()