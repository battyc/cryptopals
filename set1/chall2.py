from binascii import unhexlify, hexlify
import base64

def fixed_length_hex_xor(buff1, buff2):
	return hexlify((''.join(chr(ord(chr(index1)) ^ ord(chr(index2))) for index1, index2 in zip(unhexlify(buff1), unhexlify(buff2)))).encode('utf-8'))

def chall_two():
	string1 = "1c0111001f010100061a024b53535009181c"
	string2 = "686974207468652062756c6c277320657965"
	print(str(fixed_length_hex_xor(string1, string2).decode('ascii')))

chall_two()