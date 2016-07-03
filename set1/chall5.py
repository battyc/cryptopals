from binascii import hexlify, unhexlify

def long_to_short_hex_xor(buff1, buff2):
	return hexlify((''.join(chr(ord(chr(index1)) ^ ord(chr(index2))) for index1, index2 in zip(unhexlify(buff1), unhexlify(buff2*-(-len(buff1)//(len(buff2))))))).encode('utf-8'))

def chall_five():
	with open("chall5file.txt", "r") as f:
		file_string = hexlify(f.read().encode('ascii'))
		print(long_to_short_hex_xor(file_string, hexlify("ICE".encode('ascii'))).decode('ascii'))

chall_five()