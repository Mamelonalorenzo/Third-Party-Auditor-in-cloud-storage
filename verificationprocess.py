def main():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    
    with open("C:/Users/Lorenzo/Desktop/Test/TPA/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    
    with open('C:/Users/Lorenzo/Desktop/Test/TPA/Data.encrypted','rb') as f:
        encrypted=f.read()
        f.close()
    
    User_signature = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    
    
    with open('C:/Users/Lorenzo/Desktop/Test/TPA/Data2.encrypted','rb') as f:
        encrypted=f.read()
        f.close()
    
    TPA_signature = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
     
    f1= User_signature
    f2=TPA_signature
        
    if f1 == f2:
       print("FILE Authentic and Legit")
    else:
       print("FILE Modified!!!!!!!!!")
