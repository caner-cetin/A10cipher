import pydub
from playsound import playsound
from pydub import AudioSegment
import numpy as np
import sys
import os
import argparse
from cryptography.fernet import Fernet
from pathlib import Path
def write_key():
    #Generate a key and store it
    key = Fernet.generate_key()
    with open("encryption_key.txt", "wb") as file:
        file.write(key)
    return key
def load_key():
    return open("encryption_key.txt","rb").read()
def get_original_extension_of_file(foldername,key):
    files = Path(foldername).glob("*")
    global original_extension
    with open("extension.txt","w") as file2:
        for file in files:
            file_name, file_extension = os.path.splitext(file)
            original_extension = file_extension
        file2.write(original_extension)
    return original_extension
def load_extension():
    return open("extension.txt","r").read()
def change_extensions_in_folder(foldername,key):
    files = Path(foldername).glob("*")
    for file in files:
        base = os.path.splitext(file)[0]
        os.rename(file, base + ".AAAAA")
def decrypt_in_folder(foldername,key,original_extension):
    files = Path(foldername).glob("*")
    for file in files:
        base = os.path.splitext(file)[0]
        os.rename(file, base + original_extension)
def hill_encryption(plain, key):
    #Add a zero for every odd number
    global encrypted_text
    global mule_inv
    len_chk=0
    if ((len(plain)%2) != 0):
        plain += "0"
        len_chk = 1
    #Create Hill 2x2 matrixes
    row = 2
    col = int(len(plain)/2)
    msg2d = np.zeros((row,col), dtype=int)
    itr1 = 0
    itr2 = 0
    for i in range ((len(plain))):
        if (i%2==0):
            msg2d[0][itr1] = int(ord(plain[i])-65)
            itr1 += 1
        else:
            msg2d[0][itr2] = int(ord(plain[i])-65)
            itr2 += 1
    #Create a key
    key2d = np.zeros((2,2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3])-65
            itr3 += 1
    print(key2d)
    #Check validity of the key, first find determinant
    deter = key2d[0][0] * key2d[0][1] * key2d [1][0] * key2d [1][1]
    deter = deter % 26
    mule_inv = 0
    #Find multiplicative inverse
    for i in range(26):
        temp_inv = deter*i
        if temp_inv % 26 == 1:
            mule_inv = i
            break
        else:
            continue

    if mule_inv == -1:
        print("Invalid key")
        sys.exit()
    encrypted_text = ""
    itr_count = int(len(plain)/2)
    if len_chk == 0:
        for i in range(itr_count):
            temp1 = (msg2d[0][i] * key2d[0][0]) + (msg2d[1][i]*key2d[0][1])
            encrypted_text += chr((temp1%26)+65)
            temp2 = (msg2d[0][i] * key2d[1][0]) + (msg2d[1][i]*key2d[1][1])
            encrypted_text += chr((temp2%26)+65)
    else:
        for i in range(itr_count-1): #Subtract 1 zero we added above
            temp1 = (msg2d[0][i] * key2d[0][0]) + (msg2d[1][i]*key2d[0][1])
            encrypted_text += chr((temp1%26)+65)
            temp2 = (msg2d[0][i] * key2d[1][0]) + (msg2d[1][i]*key2d[1][1])
            encrypted_text += chr((temp2%26)+65)
    print("Encrypted text: {} ".format(encrypted_text))
    return encrypted_text
def A10_decryption(cipher,key):
    global mule_inv
    len_chk = 0
    if (len(cipher)%2) != 0:
        cipher += "0"
        len_chk = 1
    row = 2
    column = int(len(cipher)/2)
    msg2d = np.zeros((row,column), dtype=int)
    itr1 = 0
    itr2 = 0
    for i in range(len(cipher)):
        if i%2==0:
            msg2d[0][itr1] = int(ord(cipher[i])-65)
            itr1 += 1
        else:
            msg2d[1][itr2] = int(ord(cipher[i])-65)
            itr2 +=1
    #Create a key
    key2d = np.zeros((2,2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3]) - 65
            itr3 += 1
    #Find determinant
    deter = key2d[0][0]*key2d[1][1] - key2d[0][1] * key2d[1][0]
    deter = deter % 26
    #Find multiplicative inverse
    for i in range(26):
        temp_inv = deter*i
        if (temp_inv%26) == 1:
            mule_inv = i
            break
        else:
            continue
    #Adjugate matrix
    #swapping
    key2d[0][0],key2d[1][1] = key2d[1][1], key2d[0][0]
    #change signs
    key2d[0][1] *= -1
    key2d[1][0] *= -1
    key2d[0][1] = key2d[0][1] % 26
    key2d[1][0] = key2d[1][0] % 26
    mule_inv=0
    for i in range(2):
        for j in range(2):
            key2d[i][j] *= mule_inv
    for i in range(2):
        for j in range(2):
            key2d[i][j] = key2d[i][j] % 26
    decrypt_text = ""
    iteration_count=int(len(cipher)/2)
    if len_chk == 0:
        for i in range(iteration_count):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decrypt_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decrypt_text += chr((temp2 % 26) + 65)
    else:
        for i in range(iteration_count-1):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decrypt_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decrypt_text += chr((temp2 % 26) + 65)
    print("Decrypted text> {}".format(decrypt_text))
    print("and it is time for BEHEADED KAMIKAZE!...")
    playsound("Serious Sam Kamikaze scream.wav")
class FileOfType:
    def __init__(self, type):
        self.type = type
        assert type in ['dir', 'file']
    def __call__(self, path):
        if self.type == 'dir':
            if not os.path.isdir(path):
                raise argparse.ArgumentTypeError(f"{path} is not a directory")
        elif self.type == 'file':
            if not os.path.isfile(path):
                raise argparse.ArgumentTypeError(f"{path} is not a regular file")
            elif os.path.islink(path):
                raise argparse.ArgumentTypeError(f"{path} is a symbolic link")
        return path
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Change every file extension to .AAAAA in folder")
    parser.add_argument("-dir","--directory", type=FileOfType("dir"))
    parser.add_argument("-ge","-getextension",action="store_true",help="Gets extension of files in folders to decrypt in the future")
    parser.add_argument("-g", "--generate-key", dest="generate_key", action="store_true",
                        help="Whether to generate a new key or use existing")
    parser.add_argument("-e","--encrypt",action="store_true",help="Encrypts every file with .AAAAA extension key")
    parser.add_argument("-d","--decrypt",action="store_true",help="Decrypts every file with .AAAAA extension key")
    args = parser.parse_args()
    print(args)
generate_key = args.generate_key
if generate_key:
     write_key()
key = load_key()
getextension_ = args.ge
if getextension_:
    directory = args.directory
    get_original_extension_of_file(directory, key)
original_extension = load_extension()
directory_ = args.directory
encrypt_ = args.encrypt
decrypt_ = args.decrypt
directory = args.directory
if (directory_ != None) and (encrypt_ == True):
    change_extensions_in_folder(directory,key)
elif (directory_ != None) and (decrypt_ == True):
    decrypt_in_folder(directory, key, original_extension)
plaintext = "fuck..."
plaintext = plaintext.upper().replace(" ","")
key = "hill"
key = key.upper().replace(" ","")
ciphertext = hill_encryption(plaintext, key)
A10_decryption(ciphertext, key)
