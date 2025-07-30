import sys

from Cryptodome.Cipher import AES
from io import BytesIO
from base64 import b64encode, b64decode

def encrypt(password, text, create_file=False):
    for i in range(16 - len(password) % 16):
        password = password + "0"
    
    key = password.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(text.encode()))

    if create_file:
        file_out = open("encrypted.bin", "wb")
        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
        file_out.close()

    #Write to string as file
    file_out = BytesIO()
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]

    return b64encode(file_out.getvalue()).decode()

def decrypt(password, text):
    for i in range(16 - len(password) % 16):
        password = password + "0"

    file_in = BytesIO(bytes(b64decode(text.encode())))
    
    key = password.encode()
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as exp:
        print(exp)
        sys.exit(0)
    return data.decode()

def get_password():
    while(True):
        password1 = input("Enter the password:")
        password2 = input("Enter the password to confirm:")
        if password1 != password2:
            print("Passwords don't match")
            continue
        break
    return password1

if __name__ == "__main__":
    option = input("Enter encrypt/decrypt Option:")
    if option not in ["encrypt", "decrypt"]:
        print("Option not supported!")
        sys.exit(0)

    text = input("Enter Text:")
    
    password = get_password()

    if option == "encrypt":
        print(encrypt(password, text))
    else:
        print(decrypt(password, text))
