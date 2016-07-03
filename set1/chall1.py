from binascii import unhexlify
import base64

def hex_to_base64(string):
	binary_representation = unhexlify(string)
	return base64.b64encode(binary_representation)

def chall_one():
	string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
	print(hex_to_base64(string).decode('ascii'))

chall_one()