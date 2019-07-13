import os
import sys
import re
import timeit
from timeit import default_timer as timer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import glob
import pickle

def keygen(skprfPath, skaesPath):
    lamb = 256
    aeskey = os.urandom(int(lamb / 8)) # aes key here is the secret key used to do CBC encryption
    ecbkey = os.urandom(int(lamb / 8)) # ecb key here is the secret key used to do ECB encryption

    hexECBstr = "".join(["0x{0}".format(format(byte, "02x")) for byte in ecbkey]) # Translate into hex form
    with open(skprfPath, "w") as es:
        es.write(hexECBstr)
    hexAESstr = "".join(["0x{0}".format(format(byte, "02x")) for byte in aeskey])
    with open(skaesPath, "w") as fs:
        fs.write(hexAESstr)

def ecbEncrypt(text, ecbkeyByteForm):
    paddedtext = text
    while (len(paddedtext) % 16) != 0:
        paddedtext += " "
    # encrypts the paddedtext with AES-ECB-256 standard
    backend = default_backend()
    cipher = Cipher(algorithms.AES(ecbkeyByteForm), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedtext.encode(encoding='UTF-8')) + encryptor.finalize()
    cipherByteStringForm = "".join(["0x{0}".format(format(byte, "02x")) for byte in ciphertext])
    return cipherByteStringForm

def cbcEncrypt(text, cbckeyByteForm, iv):
    paddedtext = text
    while (len(paddedtext) % 16) != 0:
            paddedtext += " "
    

    backend = default_backend()
    cipher = Cipher(algorithms.AES(cbckeyByteForm), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedtext.encode(encoding='UTF-8')) + encryptor.finalize()
    cipherByteStringForm = "".join(["0x{0}".format(format(byte, "02x")) for byte in ciphertext])
    return cipherByteStringForm

def cbcEncryptFiles(filesPath, ciphertextfiles, cbckeyByteForm):# this is the function which designed to encrypt
    # all the file in the file path
    filesPath += "/*.*"
    files = glob.glob(filesPath)
    text = ""
    # encrypts the paddedtext with AES-CBC-256 standard
    iv = os.urandom(int(16))
    with open("../data/iv.txt", 'w') as ivf:
        ivf.write("".join(["0x{0}".format(format(byte, "02x")) for byte in iv]))

    for fle in files:
        with open(fle) as f:
            text = f.read()
        cipherByteString = cbcEncrypt(text, cbckeyByteForm, iv)
        intList = re.findall(r'\d+', fle)
        cipherFilePath = ciphertextfiles + "/c" + intList[0] + ".txt"
        with open(cipherFilePath, 'w') as wf:
            wf.write(cipherByteString)

def encryption(skprfPath, skaesPath, indexPath, filesPath, ciphertextfiles):
    with open(skprfPath) as ef:
        ecbkeytext = ef.read()
    with open(skaesPath) as cf:
        cbckeytext = cf.read()

    ecbkeyByteForm = bytes([int(b, 16) for b in ecbkeytext.split("0x")[1:]])
    cbckeyByteForm = bytes([int(b, 16) for b in cbckeytext.split("0x")[1:]])

    cbcEncryptFiles(filesPath, ciphertextfiles, cbckeyByteForm)

    dictionary = {}
    filesPath += "/*.*"
    files = glob.glob(filesPath)
    text = ""

    for fle in files:
        with open(fle) as f:
            text = f.read()
            keywords = text.split()

            for i in range(len(keywords)):
                cipherByteStringForm = ecbEncrypt(keywords[i], ecbkeyByteForm)

                if cipherByteStringForm in dictionary:
                    dictionary[cipherByteStringForm] += " " + getCipherName(fle)
                else:
                    dictionary[cipherByteStringForm] = getCipherName(fle)
            text = ""
    for key, value in dictionary.items():
        print(key, value)
    with open(indexPath, 'wb') as ip:
        pickle.dump(dictionary, ip)

def getCipherName(fle):
    intList = re.findall(r'\d+', fle)
    cipherFilePath = "c" + intList[0] + ".txt"
    return cipherFilePath

def token(keyword, skprfPath, tokenPath):
    with open(skprfPath) as ef:
        ecbkeytext = ef.read()

    paddedkeyword = keyword
    ecbkeyByteForm = bytes([int(b, 16) for b in ecbkeytext.split("0x")[1:]])
    cipherByteStringForm = ecbEncrypt(keyword, ecbkeyByteForm)

    with open(tokenPath, "w") as tt:
        tt.write(cipherByteStringForm)
    print(cipherByteStringForm)

def search(indexPath, tokenPath, cipherTextPath, skaesPath):
    start_time = timeit.default_timer()
    with open(skaesPath) as kf:
        aeskeytext = kf.read()

    with open("../data/iv.txt") as iv:
        aniv = iv.read()

    cipherTextPath += "/"

    with open(indexPath, 'rb') as ip:
        dictionary = pickle.loads(ip.read())

    with open(tokenPath) as tt:
        tokenValue = tt.read()

    if tokenValue in dictionary:
        result = dictionary[tokenValue]
        elapsed = timeit.default_timer() - start_time
        print("time to find all encrypted files: " + str(elapsed))
        fileNames = result.split()
        with open("../data/result.txt", "w") as wb:
            wb.write(str(fileNames) + "\n")
        print(fileNames)
        for fileName in fileNames:
            with open(cipherTextPath + fileName) as ct:
                encryptedContent = ct.read()
            decryptedAnswer = decCBC(skaesPath, encryptedContent)
            print(fileName + " " + decryptedAnswer)
            with open("../data/result.txt", "a") as wr:
                wr.write(fileName + " " + decryptedAnswer + "\n")

def decCBC(skaesPath, encryptedContent): # this is our AES CBC decryption method
    start_time = timeit.default_timer()
    with open(skaesPath) as kf:
        aeskeytext = kf.read()
    with open("../data/iv.txt") as iv:
        siv = iv.read()
    backend = default_backend()
    key = bytes([int(b, 16) for b in aeskeytext.split("0x")[1:]])
    iv = bytes([int(b, 16) for b in siv.split("0x")[1:]])

    cipherbytes = bytes([int(b, 16) for b in encryptedContent.split("0x")[1:]])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decryptedstr = decryptor.update(cipherbytes) + decryptor.finalize()

    # turns the byte string back into a hexadecimal string and translates that to readable text
    result = "".join(["{0}".format(format(byte, "02x")) for byte in decryptedstr])
    translatedResult = bytes.fromhex(result).decode()
    elapsed = timeit.default_timer() - start_time
    print("time to decrypt file : " + str(elapsed))
    return translatedResult

def main():
    if sys.argv[1] == "keygen":
        keygen(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "encryption":
        start_time = timeit.default_timer()
        encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        elapsed = timeit.default_timer() - start_time
        print("total time = " + str(elapsed))
    elif sys.argv[1] == "token":
        token(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "search":
        start_time = timeit.default_timer()
        search(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        elapsed = timeit.default_timer() - start_time
        print("total time = " + str(elapsed))


main()
