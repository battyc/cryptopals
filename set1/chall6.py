import operator
from binascii import hexlify, unhexlify, a2b_base64

char_freq_dict = {
	' ': 25.0,
	'e':12.7,
	't':9.1,
	'a':8.2,
	'o':7.5,
	'i':7.0,
	'n':6.7,
	's':6.3,
	'h':6.1,
	'r':6.0,
	'd':4.3,
	'l':4.0,
	'u':2.8,
	'c':2.8,
	'm':2.4,
	'w':2.4,
	'f':2.2,
	'y':2.0,
	'g':2.0,
	'p':1.9,
	'b':1.5,
	'v':1.0,
	'k':0.8,
	'x':0.2,
	'j':0.2,
	'q':0.1,
	'z':0.1,
}


def evaluate_one_char_xor(string):
	scores = []
	for num in range(32,126):
		vary = long_to_short_hex_xor(string, format(num,"x"))
		plaintext = str(unhexlify(vary))
		char_freq_list = get_char_freq_list_from_string(plaintext)
		scores.append([score_by_char_freq(char_freq_list), unhexlify(vary), num])
	scores.sort(key= lambda x: x[0], reverse=True)
	return scores[0]

def get_char_freq_list_from_string(string):
	ansList = {}
	for c in string:
		line = c
		if c in ansList:
			ansList[c] += 1
		else:
			ansList[c] = 1
	sortedAns = sorted(ansList.items(), key=operator.itemgetter(1), reverse=True)
	return sortedAns

def score_by_char_freq(char_freq_list):
	score = 0
	for entry in char_freq_list:
		if entry[0].lower() in char_freq_dict:
			score += char_freq_dict[entry[0].lower()]
	return score

def long_to_short_hex_xor(buff1, buff2):
	return hexlify((''.join(chr(ord(chr(index1)) ^ ord(chr(index2))) for index1, index2 in zip(unhexlify(buff1), unhexlify(buff2*-(-len(buff1)//(len(buff2))))))).encode('utf-8'))

def find_hamming_dist(byte_arr1, byte_arr2):
	hamm_dist = 0
	for byte1, byte2 in zip(byte_arr1, byte_arr2):
		for bit1, bit2 in zip(format(int(byte1), '08b'), format(int(byte2), '08b')):
			if bit1 != bit2:
				hamm_dist += 1
	return hamm_dist

def normalized_hamm_dist(all_bytes, keysize):
	hamm_sum = 0
	for start_ind in range(int(len(all_bytes)/keysize) - 1):
		hamm_sum += find_hamming_dist(all_bytes[start_ind*keysize:(start_ind +1)*keysize],all_bytes[(start_ind+1)*keysize:(start_ind +2)*keysize])
	return hamm_sum/(len(all_bytes)/keysize -1)/keysize


	'''
	Break Vignere Cipher
	'''
def chall_six():
	with open("chall6file.txt", "r") as f:
		all_bytes = ""
		
		for line in f:
			all_bytes += line.strip()
		all_bytes = a2b_base64(all_bytes)

		hamm_dist_list = []

		# get hamming distance for each possible key
		for keysize in range(2, 40):
			hamm_dist_list.append([keysize, normalized_hamm_dist(all_bytes, keysize)])
		hamm_dist_list.sort(key= lambda ksize: ksize[1])

		print(hamm_dist_list)
		key_len = hamm_dist_list[0][0]
		
		transposed = [bytearray() for n in range(key_len)]

		for i, bytes in enumerate(all_bytes):
			transposed[i%key_len].append(bytes)

		ans_key = bytearray()

		for ind, block in enumerate(transposed):
			top_score = evaluate_one_char_xor(hexlify(block).decode('utf-8'))
			ans_key.append(top_score[2])
		print(ans_key.decode('utf-8'))

chall_six()