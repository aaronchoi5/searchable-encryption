import os
import sys
import re
from timeit import default_timer as timer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import glob


def keygen(skprfPath, skaesPath):
	lamb = 256
	aeskey = os.urandom(int(lamb/8))
	ecbkey = os.urandom(int(lamb/8))

	hexECBstr = "".join(["0x{0}".format(format(byte,"02x")) for byte in ecbkey])
	with open(skprfPath, "w") as fs:
		fs.write(hexECBstr)
	hexAESstr = "".join(["0x{0}".format(format(byte,"02x")) for byte in aeskey])
	with open(skaesPath, "w") as fs:
		fs.write(hexAESstr)

def ecbEncrypt(paddedtext, ecbkeyByteForm):
	#encrypts the paddedtext with AES-ECB-256 standard
	backend = default_backend()
	cipher = Cipher(algorithms.AES(ecbkeyByteForm), modes.ECB(), backend=backend)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(paddedtext.encode(encoding='UTF-8')) + encryptor.finalize()
	cipherByteStringForm = "".join(["0x{0}".format(format(byte,"02x")) for byte in ciphertext])
	return cipherByteStringForm

def cbcEncrypt(paddedtext, cbckeyByteForm):
	#encrypts the paddedtext with AES-CBC-256 standard
	iv = os.urandom(int(16))
	with open("./data/iv.txt", 'w') as ivf: 
		ivf.write("".join(["0x{0}".format(format(byte,"02x")) for byte in iv]))

	backend = default_backend()
	cipher = Cipher(algorithms.AES(cbckeyByteForm), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(paddedtext.encode(encoding='UTF-8')) + encryptor.finalize()
	cipherByteStringForm = "".join(["0x{0}".format(format(byte,"02x")) for byte in ciphertext])
	return cipherByteStringForm

def encryptFiles(filesPath, ciphertextfiles, cbckeyByteForm):
	filesPath +=  "/*.*"
	files = glob.glob(filesPath)
	text = ""

	for fle in files:
		with open(fle) as f:
			text = f.read()
		paddedtext = text
		while((len(paddedtext) % 16) != 0):
			paddedtext += " "
		cipherByteString = cbcEncrypt(paddedtext, cbckeyByteForm)
		print(fle)
		intList = re.findall(r'\d+', fle)
		print(intList)
		cipherFilePath = ciphertextfiles + "/c" + intList[0]
		with open(cipherFilePath, 'w') as wf:
			wf.write(cipherByteString)

def encryption(skprfPath, skaesPath, indexPath, filesPath, ciphertextfiles):
	with open(skprfPath) as ef:
		ecbkeytext = ef.read()
	with open(skaesPath) as cf:
		cbckeytext = cf.read()

	ecbkeyByteForm = bytes([int(b,16) for b in ecbkeytext.split("0x")[1:]])
	cbckeyByteForm = bytes([int(b,16) for b in cbckeytext.split("0x")[1:]])

	encryptFiles(filesPath, ciphertextfiles,cbckeyByteForm)

	dictionary = {}
	filesPath +=  "/*.*"
	files = glob.glob(filesPath)
	text = ""

	for fle in files:
		with open(fle) as f:
			text = f.read()
			keywords = text.split()

			for i in range(len(keywords)):
				paddedtext = keywords[i]
				while((len(paddedtext) % 16) != 0):
					paddedtext += " "

				cipherByteStringForm = ecbEncrypt(paddedtext, ecbkeyByteForm)

				if(cipherByteStringForm in dictionary):
					dictionary[cipherByteStringForm] += " " + fle
				else:
					dictionary[cipherByteStringForm] = fle

				print(dictionary[cipherByteStringForm])

			text = ""

	with open(indexPath, "w") as f:
		for key, values in dictionary.items():
			f.write(key + " " + values + "\n")

def token(skprfPath, keyword, tokenPath):
	with open(skprfPath) as ef:
		ecbkeytext = ef.read()
	paddedkeyword = keyword
	ecbkeyByteForm = bytes([int(b, 16) for b in ecbkeytext.split("0x")[1:]])
	
	while((len(paddedtext) % 16) != 0):
		paddedkeyword += " "
	cipherByteStringForm = ecbEncrypt(paddedkeyword, ecbkeyByteForm)
	with open(tokenPath, "w") as tt:
		tt.write(cipherByteStringForm)
	print(cipherByteStringForm)

def search(blah, blah2):
	a = 1

#cipherbytes = bytes([int(b,16) for b in cipherStringForm.split("0x")[1:]])
			#cipher = Cipher(algorithms.AES(ecbkeyByteForm), modes.ECB(), backend=backend)
			#decryptor = cipher.decryptor()
			#decryptedstr = decryptor.update(cipherbytes) + decryptor.finalize()
			#result =  "".join(["{0}".format(format(byte,"02x")) for byte in decryptedstr])
			#translatedResult = bytearray.fromhex(result).decode()

def main():
	if sys.argv[1] == "keygen":
		keygen(sys.argv[2], sys.argv[3])
	elif sys.argv[1] == "encryption":
		encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
	elif sys.argv[1] == "token":
		token(sys.argv[2], sys.argv[3])
	elif sys.argv[1] == "search":
		search(sys.argv[2], sys.argv[3])
main()
