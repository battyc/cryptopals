import operator
from binascii import hexlify, unhexlify

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
		if entry[0] in ['E', 'e', 'T', 't', 'A', 'O', 'o', 'I','i','N','n','S','s','H','h','R','r']:
			score += entry[1]
		elif not entry[0].isalpha() and entry[0] not in [' ', ',',"'",'.']:
			score -= 10
	return score

def long_to_short_hex_xor(buff1, buff2):
	return hexlify((''.join(chr(ord(chr(index1)) ^ ord(chr(index2))) for index1, index2 in zip(unhexlify(buff1), unhexlify(buff2*-(-len(buff1)//(len(buff2))))))).encode('utf-8'))

def chall_four():
	with open("chall4file.txt", "r") as f:
		fileList = f.readlines()
		for line in fileList:
			top_score = evaluate_one_char_xor(line.replace('\n', ""))
			if top_score[0] >= 5:
				print(top_score[1].decode('ascii'))

chall_four()