# searchable-encryption

This is my implementation of searchable encryption. This probram can generate it's own keys for encryption and decryption. You can specify where the files to be encrypted and decrypted are. 

After running the keygen and generating encrypted files and generating a token, by providing a keyword that you want to search for across the encrypted files, we can store the results of our queries into a generated results.txt file.


Language: Python3 
Platform: Linux(Ubuntu 16.04), Windows 10 and Mac os 10.13.4 
Reference: Cryptography library in Python
To run the python program follow these instructions:

For key generation: python main.py keygen ECBkeyPath(for example ../data/ECBkey.txt) AESkeyPath(for example ../data/AESkey.txt)
example run:

python3 main.py keygen ../data/ECBkey.txt ../data/AESkey.txt

For encryption: python main.py encryption ECBkeyPath AESkeyPath indexPath(where you want the index file to be) plainTextfilesPath(where you have prepared files to be read) cipherTextfilesPath(where you want the encrypted files to be)
example run:

python3 main.py encryption ../data/ECBkey.txt ../data/AESkey.txt ../data/index.txt ../data/texts ../data/ciphertextfiles

For token generation: python main.py token keyword(word you want to search for) ECBkeyPath tokenPath(where you want to token file to be)
example run:

python3 main.py token packers ../data/ECBkey.txt ../data/token.txt

For search: python main.py search indexPath(where did you specify the index file was?) tokenPath(where did you specify the token file was) ciphertextFilesPath(where did you specify all the ciphertextFiles  to be?) AESkeyPath(Where did you specify you wanted the AES key file to be stored?)
example run:

python3 main.py search ../data/index.txt ../data/token.txt ../data/ciphertextfiles ../data/AESkey.txt
