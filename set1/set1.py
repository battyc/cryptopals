'''
Author: Chris Batty

Solutions to set 1 of the challenges posed at cryptopals.com

So far solutions for challenges 1-5 are included
'''
from binascii import hexlify, unhexlify
from itertools import cycle
import base64
import operator
import sys

char_freq_dict = [
	('E',12.7),
	('T',9.1),
	('A',8.2),
	('O',7.5),
	('I',7.0),
	('N',6.7),
	('S',6.3),
	('H',6.1),
	('R',6.0),
	('D',4.3),
	('L',4.0),
	('U',2.8),
	('C',2.8),
	('M',2.4),
	('W',2.4),
	('F',2.2),
	('Y',2.0),
	('G',2.0),
	('P',1.9),
	('B',1.5),
	('V',1.0),
	('K',0.8),
	('X',0.2),
	('J',0.2),
	('Q',0.1),
	('Z',0.1),
]

def hex_to_base64(string):
	binary_representation = unhexlify(string)
	return base64.b64encode(binary_representation)

def fixed_length_hex_xor(buff1, buff2):
	return hexlify((''.join(chr(ord(chr(index1)) ^ ord(chr(index2))) for index1, index2 in zip(unhexlify(buff1), unhexlify(buff2)))).encode('utf-8'))

def long_to_short_hex_xor(buff1, buff2):
	return hexlify((''.join(chr(ord(chr(index1)) ^ ord(chr(index2))) for index1, index2 in zip(unhexlify(buff1), unhexlify(buff2*-(-len(buff1)//len(buff2)))))).encode('utf-8'))

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

def evaluate_one_char_xor(string):
	scores = []
	for num in range(33,126):
		vary = long_to_short_hex_xor(string, format(num,"x"))
		plaintext = str(unhexlify(vary))
		char_freq_list = get_char_freq_list_from_string(plaintext)
		scores.append([score_by_char_freq(char_freq_list), unhexlify(vary)])
	scores.sort(key= lambda x: x[0], reverse=True)
	return scores[0]

def chall_one():
	string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
	print(hex_to_base64(string).decode('ascii'))

def chall_two():
	string1 = "1c0111001f010100061a024b53535009181c"
	string2 = "686974207468652062756c6c277320657965"
	print(str(fixed_length_hex_xor(string1, string2).decode('ascii')))
	
def chall_three():
	string="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".encode('ascii')
	top_score = evaluate_one_char_xor(string)
	print(top_score[1].decode('ascii'))

def chall_four():
	#f = open(sys.argv[1], "r")
	f = open("chall4file.txt", "r")
	fileList = f.readlines()
	for line in fileList:
		top_score = evaluate_one_char_xor(line.replace('\n', ""))
		if top_score[0] >= 5:
			print(top_score[1].decode('ascii'))

def chall_five():
	#f = open(sys.argv[1], "r")
	f = open("chall5file.txt", "r")
	file_string = hexlify(f.read().encode('ascii'))
	print(long_to_short_hex_xor(file_string, hexlify("ICE".encode('ascii'))).decode('ascii'))

# Uncomment the challenge you would like to run.

#chall_one()	
#chall_two()
#chall_three()
#chall_four()
chall_five()