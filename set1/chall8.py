from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

def analyze_ecb_line(byte_data):
	transposed = [bytearray() for n in range(16)]

	for index , bytes in enumerate(byte_data):
		transposed[index%16].append(bytes)

	repeat_count = 0
	for entry in transposed:	
		value_occurance = {}
		for byte in entry:
			if byte in value_occurance:
				#value_occurance[byte] += 1
				repeat_count += 1
			else:
				value_occurance[byte] = 1
	return repeat_count

line_repeats = []

with open("chall8file.txt", "r") as f:
	for line in f:
		line_repeats.append([analyze_ecb_line(unhexlify(line.strip())), line.strip()])

line_repeats.sort(key= lambda x: x[0], reverse=True)
print(line_repeats[0])
		