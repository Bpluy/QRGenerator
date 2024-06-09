from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import socket
import segno

key = base64.b64decode("LPjR6pHBsx2VvuYNYAaRZfGKsomvqsh3vAODL46dENw=")
iv = base64.b64decode("nXJhi/OyX83gULxJv1UARQ==")

def encrypt_string(plain_text):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP = '95.174.93.97'
PORT = 11333
connection.connect((IP, PORT))
rd = connection.recv(1024)
print(rd.decode('utf8'))
message = encrypt_string("getSlotIDs")
connection.send(message.encode('utf8'))
rd = connection.recv(1024).decode('utf8').split(" ")
for ID in rd:
    if ID != '':
        qr = segno.make_qr(base64.b64encode(f"startGame {ID}".encode('utf8')))
        qr.save(f"qrStart{ID}.png", dark = '#000', border = 1, scale = 20)
connection.close()
