from fsplit.filesplit import FileSplit
import PySimpleGUI as sg

filename =sg.PopupGetFile('Select File to Upload')

fs = FileSplit(filename, splitsize=30000000, output_dir='C:/Users/Lorenzo/Desktop/Test/User')
fs.split(include_header = False)

#key
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password_provided = "This is a test" 
password = password_provided.encode() 
salt = b'\xefK\xaaQ\\\xdb\x13t\xbb\r\x972\x8f\x12O\x1c' 
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))

#AES
from cryptography.fernet import Fernet
import glob

fernet = Fernet(key)

for file_name in glob.glob('C:/Users/Lorenzo/Desktop/Test/User/*'):
    #print(file_name) 
    with open(file_name,'rb') as f:
        data= f.read()
        encrypted=fernet.encrypt(data)
        for line in file_name:
            with open( file_name +'.enc','wb') as f:
                f.write(encrypted)
                
#hashing
import hashlib

sha256_hash = hashlib.sha256()

for file_encoded in glob.glob('C:/Users/Lorenzo/Desktop/Test/User/*.enc'):
    #print(file_encoded)
    with open (file_encoded , 'rb')as p:
        for byte_block in iter (lambda: p.read(4096),b""):
            sha256_hash.update(byte_block)
            #print(sha256_hash.hexdigest())
        for line in file_encoded:
            with open(file_encoded+'.txt','w+') as h:
                h.write(sha256_hash.hexdigest())
                
#transfert data enc and hash
import shutil
import glob

txt = glob.glob('C:/Users/Lorenzo/Desktop/Test/User/*.txt')
for f in txt:
    shutil.move(f, 'C:/Users/Lorenzo/Desktop/Test/TPA')  
       
enc = glob.glob('C:/Users/Lorenzo/Desktop/Test/User/*.enc')
for f in enc:
    shutil.move(f, 'C:/Users/Lorenzo/Desktop/Test/Server')  

#Deleting Junk
import os

folder= "C:/Users/Lorenzo/Desktop/Test/User/"
for the_file in os.listdir(folder):
    file_path = os.path.join(folder, the_file)
    if os.path.isfile(file_path):
            os.unlink(file_path)



               
#concatonation               
import io  

files= glob.glob('C:/Users/Lorenzo/Desktop/Test/TPA/*.txt')

lines = io.StringIO()
for file_dir in files:
    with open(file_dir, 'r') as file:
        lines.write(file.read())
        lines.write('\n')
lines.seek(0)
with open ('C:/Users/Lorenzo/Desktop/Test/TPA/data.sha', 'w+') as file:
    file.write(lines.read())

#key Gen

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key.public_key()

from cryptography.hazmat.primitives import serialization

pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
with open('C:/Users/Lorenzo/Desktop/Test/TPA/private_key.pem', 'wb') as f:
    f.write(pem)

pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
with open('C:/Users/Lorenzo/Desktop/Test/TPA/public_key.pem', 'wb') as f:
    f.write(pem)
    
#key import
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
with open('C:/Users/Lorenzo/Desktop/Test/TPA/private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
with open('C:/Users/Lorenzo/Desktop/Test/TPA/public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
#encrypt with DSA public
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

with open ('C:/Users/Lorenzo/Desktop/Test/TPA/data.sha', 'rb') as f:
    message = f.read()
    f.close()
    
encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

with open ('C:/Users/Lorenzo/Desktop/Test/TPA/Data.encrypted','wb') as f:
    f.write(encrypted)
    f.close()  
    
dir_name2 = "C:/Users/Lorenzo/Desktop/Test/TPA/"
test = os.listdir(dir_name2)

for item in test:
    if item.endswith(".txt"):
        os.remove(os.path.join(dir_name2, item))
    if item.endswith(".sha"):
        os.remove(os.path.join(dir_name2,item))

           

