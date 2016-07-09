from Crypto.Cipher import AES
from binascii import a2b_base64

key = b'YELLOW SUBMARINE'
cipher = AES.new(key, AES.MODE_ECB)

all_bytes = b''
solved = b''
with open("chall7file.txt", "r") as f:
	print(cipher.decrypt(a2b_base64(f.read())).decode('utf-8'))
