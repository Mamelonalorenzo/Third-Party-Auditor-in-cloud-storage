
import shutil
import glob

enc = glob.glob('C:/Users/Lorenzo/Desktop/Test/Server/*.enc')
for f in enc:
    shutil.copy(f, 'C:/Users/Lorenzo/Desktop/Test/TPA')
#hashing
import hashlib

sha256_hash = hashlib.sha256()

for file_encoded in glob.glob('C:/Users/Lorenzo/Desktop/Test/TPA/*.enc'):
    #print(file_encoded)
    with open (file_encoded , 'rb')as p:
        for byte_block in iter (lambda: p.read(4096),b""):
            sha256_hash.update(byte_block)
            #print(sha256_hash.hexdigest())
        for line in file_encoded:
            with open(file_encoded+'.txt','w+') as h:
                h.write(sha256_hash.hexdigest())
#concat                
import io  

files= glob.glob('C:/Users/Lorenzo/Desktop/Test/TPA/*.txt')

lines = io.StringIO()
for file_dir in files:
    with open(file_dir, 'r') as file:
        lines.write(file.read())
        lines.write('\n')
lines.seek(0)
with open ('C:/Users/Lorenzo/Desktop/Test/TPA/data2.sha', 'w+') as file:
    file.write(lines.read())

#DSA key import
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

with open('C:/Users/Lorenzo/Desktop/Test/TPA/public_key.pem', "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

#encrypt with DSA public
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

with open ('C:/Users/Lorenzo/Desktop/Test/TPA/data2.sha', 'rb') as f:
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

with open ('C:/Users/Lorenzo/Desktop/Test/TPA/Data2.encrypted','wb') as f:
    f.write(encrypted)
    f.close()

#delete junk
import os

dir_name = "C:/Users/Lorenzo/Desktop/Test/TPA/"
test = os.listdir(dir_name)
for item in test:
    if item.endswith(".txt"):
        os.remove(os.path.join(dir_name, item)) 
    if item.endswith(".enc"):
        os.remove(os.path.join(dir_name, item))
    if item.endswith(".sha"):
        os.remove(os.path.join(dir_name, item))
        
import verificationprocess
verificationprocess.main()


