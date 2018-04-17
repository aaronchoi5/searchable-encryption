import os
import sys
from timeit import default_timer as timer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import glob


def keygen(skprfPath, skaesPath):
    lamb = 256
    aeskey = os.urandom(int(lamb / 8))
    ecbkey = os.urandom(int(lamb / 8))

    hexECBstr = "".join(["0x{0}".format(format(byte, "02x")) for byte in ecbkey])
    with open("../data/ECBkey.txt", "w") as fs:
        fs.write(hexECBstr)
    hexAESstr = "".join(["0x{0}".format(format(byte, "02x")) for byte in aeskey])
    with open("../data/AESkey.txt", "w") as fs:
        fs.write(hexAESstr)


def encryption(skprfPath, skaesPath, index, filesPath, ciphertextfiles):
	filesPath +=  "/*.*"
	print(filesPath)
	files = glob.glob(filesPath)
	print(files)
	text = ""
	for fle in files:
		with open(fle) as f:
			text += f.read()
	print(text)



def token(blah, blah2):
    sup = 0


def search(blah, blah2):
    a = 1


def hashToHex(string):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    messageBytesArray = string.encode('utf-8')
    digest.update(messageBytesArray)

    bytesVar = digest.finalize()
    hexstr = "".join(["{0}".format(format(byte, "02x")) for byte in bytesVar])
    byteBin = bin(int(hexstr, 16))[2:].zfill(8)
    return byteBin


def cbcenc():
    with open("../data/key.txt") as kf:
        keytext = kf.read()
    with open("../data/plainText.txt") as pf:
        plaintext = pf.read()
    paddedtext = plaintext

    # padding the text because the text has to be divisible by the block size which 128 bits or 16 bytes in AES
    while ((len(paddedtext) % 16) != 0):
        paddedtext += " "

    # iv must be the same size as the block size which is 16 bytes in AES
    iv = os.urandom(int(16))
    ivstring = "".join(["0x{0}".format(format(byte, "02x")) for byte in iv])
    key = bytes([int(b, 16) for b in keytext.split("0x")[1:]])

    # writes iv to a file
    with open("../data/iv.txt", 'w') as ivf:
        ivf.write("".join(["0x{0}".format(format(byte, "02x")) for byte in iv]))

    # encrypts the paddedtext with AES-CBC-256 standard
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedtext.encode(encoding='UTF-8')) + encryptor.finalize()
    # writes the ciphertext to a file
    with open("../data/ciphertext.txt", 'w') as cf:
        cf.write("".join(["0x{0}".format(format(byte, "02x")) for byte in ciphertext]))
    print(ciphertext)


def cbcdec():
    with open("../data/key.txt") as kf:
        keytext = kf.read()
    with open("../data/iv.txt") as ivf:
        ivtext = ivf.read()
    with open("../data/ciphertext.txt") as cf:
        ciphertext = cf.read()

    # decrypts the paddedtext with AES-CBC-256 standard
    backend = default_backend()
    key = bytes([int(b, 16) for b in keytext.split("0x")[1:]])
    iv = bytes([int(b, 16) for b in ivtext.split("0x")[1:]])
    cipherbytes = bytes([int(b, 16) for b in ciphertext.split("0x")[1:]])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decryptedstr = decryptor.update(cipherbytes) + decryptor.finalize()

    # turns the byte string back into a hexadecimal string and translates that to readable text
    result = "".join(["{0}".format(format(byte, "02x")) for byte in decryptedstr])
    translatedResult = bytearray.fromhex(result).decode()
    with open("../data/result.txt", 'w') as rf:
        rf.write(translatedResult)
    print(translatedResult)


def main():
    if sys.argv[1] == "keygen":
        keygen(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "encryption":
        encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif sys.argv[1] == "token":
        token(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "search":
        search(sys.argv[2], sys.argv[3])
